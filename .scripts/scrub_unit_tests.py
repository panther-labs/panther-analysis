"""This example shows how you can use loganon in your CI pipeline to sanitize unit tests in Panther
detections."""

import json
import re
import subprocess
import sys

from loganon import Anonymizer, all_rules_list
from ruamel.yaml import YAML

yaml = YAML(typ="safe")
anonymizer = Anonymizer(all_rules_list())

def main():
    files = sys.argv[1:]
    if not files:
        result = subprocess.run(["git", "diff", "--name-only", "--cached", "--diff-filter=AM"], capture_output=True, text=True)
        files = result.stdout.splitlines()

    for file in files:
        if not file.endswith(".yml"):
            continue

        with open(file, "r") as f:
            raw_text = f.read()
            rule = yaml.load(raw_text)

        new_logs = []
        for test in rule.get("Tests", []):
            log = test.get("Log", "")
            new_log = anonymizer.anonymize(json.dumps(log, indent=2))
            new_logs.append(new_log)

        # Replace the original log
        pattern = re.compile(r"^(\s+)Log:", re.MULTILINE)
        # Find all matches
        final_text = ""
        while True:
            match = pattern.search(raw_text)
            print(match)
            if match:
                indent = len(match.group(1))
                log_text = json.dumps(json.loads(new_logs.pop(0)), indent=2)
                log_text = log_text.replace("\n", "\n" + " "*(indent))
                final_text += raw_text[:match.start()] + " "*indent + "Log: " + log_text + "\n"
                print(final_text)
                lines = raw_text[match.end():].splitlines()
                idx = 0
                for line in lines:
                    if len(line) > indent and line[indent] != " ":
                        break
                    idx += 1
                raw_text = "\n".join(lines[idx:])
            else:
                break

        with open(file, "w") as f:
            f.write(final_text)


if __name__ == "__main__":
    main()