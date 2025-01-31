""" This script checks all the MITRE Mappings in the Reports section of each analysis item to
ensure they follow the formal TAXXXX:TXXXX. If MITRE mappings aren't in this format, they don't
display properly in Panther's UI. """

import re
import sys
import traceback
from pathlib import Path

from panther_analysis_tool.analysis_utils import load_analysis_specs

# All MITRE Tags must match this regex pattern
MITRE_PATTERN = re.compile("^TA\d+\:T\d+(\.\d+)?$")


def main(path: Path) -> bool:
    # Ignore any schema test files
    #   Schema tests can't be loaded by panther_analysis_tool because each file contains multiple
    #   YAML documents.
    # Also ignore any JSON files stored under indexes, since they aren't analysis items but get
    #   caught by the load_analysis_specs function
    ignore_files = []
    ignore_files += list(path.glob("**/*_tests.y*ml"))
    ignore_files += list(path.glob("indexes/*"))

    # Load Repo
    analysis_items = load_analysis_specs([path], ignore_files=ignore_files)

    items_with_invalid_mappings = []  # Record all items with bad tags
    for analysis_item in analysis_items:
        rel_path = analysis_item[0]  # Relative path to YAML file
        spec = analysis_item[2]  # YAML spec as a dict

        try:
            bad_tags = []  # Record the invalid tags for this analysis item
            if reports := spec.get("Reports"):
                if mitre := reports.get("MITRE ATT&CK"):
                    for mapping in mitre:
                        if not MITRE_PATTERN.match(mapping):
                            bad_tags.append(mapping)

            if bad_tags:
                items_with_invalid_mappings.append({"rel_path": rel_path, "bad_tags": bad_tags})
        except Exception:
            print("Unable to test file: " + rel_path)
            print(traceback.format_exc())

    if items_with_invalid_mappings:
        print("❌ Some items had invalid MITRE mapping formats:")
        print()
        for invalid_item in items_with_invalid_mappings:
            print(invalid_item.get("rel_path", "<UNKNOWN PATH>"))
            for bad_tag in invalid_item.get("bad_tags", []):
                print("\t" + bad_tag)
            print()

        print(
            (
                "To ensure that your MITRE mappings are correctly displayed in the Panther "
                "console, make sure your MITRE mappings are formatted like 'TA0000:T0000'."
            )
        )
    else:
        print("✅ No invalid MITRE mappings found! You're in the clear! 👍")

    return bool(items_with_invalid_mappings)


if __name__ == "__main__":
    path = Path.cwd()  # Default to current directory
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    if main(path):
        exit(1)  # Exit with error if issues were found
