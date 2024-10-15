""" Checks to see if an Analysis item was removed from the repo, and whether it was added to the
deprecated.txt file. """

import argparse
import logging
import os
import re
import subprocess

import panther_analysis_tool.command.bulk_delete as pat_delete
import panther_analysis_tool.util as pat_util

diff_pattern = re.compile(r'^-(?:RuleID|PolicyID|QueryName):\s*"?([\w.]+)"?')


def get_deleted_ids() -> set[str]:
    # Run git diff, get output
    result = subprocess.run(["git", "diff", "origin/develop", "HEAD"], capture_output=True)
    if result.stderr:
        raise Exception(result.stderr.decode("utf-8"))

    ids = set()
    for line in result.stdout.decode("utf-8").split("\n"):
        if m := diff_pattern.match(line):
            # Add the ID to the list
            ids.add(m.group(1))

    return ids


def get_deprecated_ids() -> set[str]:
    """Returns all the IDs listed in `deprecated.txt`."""
    with open("deprecated.txt", "r") as f:
        return set(f.read().split("\n"))


def check(_):
    if ids := get_deleted_ids() - get_deprecated_ids():
        print("❌ The following rule IDs may have been deleted:")
        for id_ in ids:
            print(f"\t{id_}")
        exit(1)
    else:
        print("✅ No unaccounted deletions found! You're in the clear! 👍")


def remove(args):
    api_token = args.api_token or os.environ.get("PANTHER_API_TOKEN")
    api_host = args.api_host or os.environ.get("PANTHER_API_HOST")

    if not (api_token and api_host):
        opts = []
        if not api_token:
            print("No API token was found or provided!")
            opts.append("--api-token")
        if not api_host:
            print("No API host was found or provided!")
            opts.append("--api-host")
        print(f"You can pass API credentials using {' and '.join(opts)} in your command.")
        exit(1)

    ids = list(get_deprecated_ids())

    pat_args = argparse.Namespace(
        analysis_id=ids, query_id=[], confirm_bypass=True, api_token=api_token, api_host=api_host
    )

    logging.basicConfig(
        format="[%(levelname)s][%(name)s]: %(message)s",
        level=logging.INFO,
    )

    return_code, out = pat_util.func_with_api_backend(pat_delete.run)(pat_args)

    if return_code == 1:
        if out:
            logging.error(out)
    elif return_code == 0:
        if out:
            logging.info(out)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="subcommands")

    check_help = "Check if any items have been removed and not added to deprecated.txt"
    parser_check = subparsers.add_parser("check", help=check_help)
    parser_check.set_defaults(func=check)

    remove_help = "Delete the entires listed in deprecated.txt"
    parser_remove = subparsers.add_parser("remove", help=remove_help)
    parser_remove.add_argument("--api-token", type=str, required=False)
    parser_remove.add_argument("--api-host", type=str, required=False)
    parser_remove.set_defaults(func=remove)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
