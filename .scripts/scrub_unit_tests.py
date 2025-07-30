"""This example shows how you can use loganon in your CI pipeline to sanitize unit tests in Panther
detections."""

import logging
import subprocess
import sys

from loganon import Anonymizer, all_rules_list
from ruamel.yaml import YAML

yaml = YAML(typ="rt")
anonymizer = Anonymizer(all_rules_list())

logging.basicConfig(level=logging.DEBUG)

def get_unit_tests(raw_text: str) -> dict[str, tuple[int, int]]:
    # Parse the YAML content
    spec = yaml.load(raw_text)
    if not spec:
        return {}
    
    # Our goal is to extract the span (start and end line) of each test log, and store that span by
    #   the test name. Our strategy is to first index the starting line of each item in order, then
    #   use the start of each log and the start of the following item as the span.
    # First, let's grab the starting line for each item in each test
    line_info = []
    for test in spec.get("Tests", []):
        # Store a tuple, containing the line number the test starts on, and a dict of the line
        #   number of each key in the test, and the name of the test
        # breakpoint()
        line_info.append((test["Name"], test.lc.line, {k: test.lc.key(k)[0] for k in test}))
    
    # Sort list according to starting line of each test
    line_info.sort(key=lambda x: x[1])
    
    # Now we can start extracting the spans of each log
    log_spans = {}
    for i in range(len(line_info)):
        test_name, start_line, key_lines = line_info[i]
        test_items = sorted([(k, v) for k, v in key_lines.items()], key=lambda x: x[1])
        start = None
        end = None
        for item in test_items:
            # Record the start of the log
            if item[0] == "Log":
                start = item[1]
            # If we've already found the start of the log, and the current item is after the start,
            #   then we've found the end of the log
            elif start is not None and item[1] > start:
                end = item[1]-1
                break
        # It's possible the last item in the test is the log, so we need to check for that
        if end is None:
            # If there's another test after this, we can use the start of that
            if i < len(line_info) - 1:
                _, next_start_line, _ = line_info[i+1]
                end = next_start_line - 1
            else:
                end = -1 # This is a special case for the last test in the file
        log_spans[test_name] = (start, end)
    
    # We now have the start and end of each log. There's one last thing to check: one of these
    #   spans has -1 as the end. This assumed there was no data after the unit tests, but this
    #   isn't a guarantee. We should confirm if that's true and adjust accordingly.
    toplevel_line_info = [(k, spec.lc.key(k)[0]) for k in spec]
    toplevel_line_info.sort(key=lambda x: x[1])
    if toplevel_line_info[-1][0] != "Tests":
        # Means that "tests" isn't the last entry in the file, so we should adjust the end of the
        #   last log to not be the end of the file
        # First, fine the item that comes after "Tests"
        test_idx = 0
        for i in range(len(toplevel_line_info)):
            if toplevel_line_info[i][0] == "Tests":
                test_idx = i
                break
        # Now we can adjust the end of the last log to be the end of the item after "Tests"
        for test, (start, end) in log_spans.items():
            if end == -1:
                log_spans[test] = (start, toplevel_line_info[test_idx+1][1])
                break
    
    return log_spans

def get_tests_editied_in_commit(fname: str) -> dict[str, tuple[int, int]]:
    """Compares the line numbers for each test log to those changed in the commit."""
    # First, let's get the line numbers for each test log
    with open(fname, "r") as f:
        raw_text = f.read()
        test_info = get_unit_tests(raw_text)

    # Next, we fetch the git diff for the file
    result = subprocess.run(["git", "diff", "--diff-filter=AM", "--staged", fname], capture_output=True, text=True)
    # Git diff outputs the adjusted lines like
    #   @@ -12,11 +12,116 @@
    # where ther first pair of number is the starting line and line count of the removed span, and
    #   the second pair is the starting line and line count of the added span.
    logging.debug(f"Git diff: {result.stdout}")
    span_specs = [r for r in result.stdout.splitlines() if r.startswith("@@")]
    # We explicitly just want to know what lines were added
    spans = []
    for span_spec in span_specs:
        # Ignore spans that were just removals
        if "+" not in span_spec:
            continue
        # Now we can extract the span
        span = span_spec.split("+")[1].split(" ")[0]
        # Convert to a tuple of ints
        span = tuple(int(x) for x in span.split(","))
        spans.append((span[0], span[0]+span[1]))
    logging.debug(f"Found {len(spans)} spans in commit")
    for span in spans:
        logging.debug(f"Span: {span}")
    
    # Finally, we compare the start and end of each test log to the spans of the added lines, and
    #   look for overlap
    edited_tests = set()
    for test_name, (start, end) in test_info.items():
        for span in spans:
            if not (end < span[0] or start > span[1]):
                edited_tests.add(test_name)
                break
    return {k: v for k, v in test_info.items() if k in edited_tests}

def get_files_edited_in_commit():
    """Very simply returns the files that were edited in the commit."""
    result = subprocess.run(["git", "diff", "--name-only", "--cached", "--diff-filter=AM"], capture_output=True, text=True)
    files = result.stdout.splitlines()
    return files

def main(mode: str = "cli"):
    """Main function. Has 2 modes: cli and commit; the former is when the script is invoked from
    the command line, and the later is when the script is used from inside a precommit hood."""
    logging.info(f"Running in {mode} mode")
    files = sys.argv[1:]
    if mode == "commit":
        files = get_files_edited_in_commit()
    logging.info(f"Found {len(files)} files to process")
    
    for file in files:
        if not file.endswith(".yml"):
            continue
        logging.info(f"Processing {file}")

        with open(file, "r") as f:
            raw_text = f.read()
            test_info = get_unit_tests(raw_text)
        if mode == "commit":
            test_info = get_tests_editied_in_commit(file)
        
        # Anonymize the tests. We work backwards so that we don't mess up the line numbers if our
        #   replacement has a different length than the original
        raw_lines = raw_text.splitlines()
        for _, (start, end) in sorted(test_info.items(), key=lambda x: x[1][0], reverse=True):
            test_text = "\n".join(raw_lines[start:end])
            indent = len(test_text) - len(test_text.lstrip())
            test_text = test_text.replace("Logs:", "", 1).strip()
            new_text = indent*" " + anonymizer.anonymize(test_text)
            raw_lines = raw_lines[:start] + new_text.splitlines() + raw_lines[end:]
        raw_text = "\n".join(raw_lines)

        with open(file, "w") as f:
            f.write(raw_text)
        
        if mode == "commit":
            # Now we need to add the file back to the git index
            subprocess.run(["git", "add", file], check=True)
        
        logging.info(f"Done processing {file}; replaced {len(test_info)} tests")



if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        main("commit")