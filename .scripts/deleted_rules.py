"""Checks to see if an Analysis item was removed from the repo, and whether it was added to the
deprecated.txt file."""

import logging
import re
import subprocess
from typing import Optional

import panther_analysis_tool.command.bulk_delete as pat_delete
import panther_analysis_tool.util as pat_util
import typer

diff_pattern = re.compile(r'^[+-](?:RuleID|PolicyID|QueryName):\s*"?(.+?)["\n]')


def get_deleted_ids() -> set[str]:
    # Run git diff, get output
    result = subprocess.run(
        ["git", "diff", "origin/develop", "HEAD"], capture_output=True
    )
    if result.stderr:
        raise Exception(result.stderr.decode("utf-8"))

    # Track specific IDs that are added and deleted
    added_ids = set()
    deleted_ids = set()

    for line in result.stdout.decode("utf-8").split("\n"):
        if m := diff_pattern.match(line):
            id_value = m.group(1)
            if line.startswith("+"):
                added_ids.add(id_value)
            elif line.startswith("-"):
                deleted_ids.add(id_value)

    # Only consider an ID as deleted if it was deleted but not added back
    return deleted_ids - added_ids


def get_deprecated_ids() -> set[str]:
    """Returns all the IDs listed in `deprecated.txt`."""
    with open("deprecated.txt", "r") as f:
        return set(f.read().split("\n"))


def check():
    """Check if any items have been removed and not added to deprecated.txt"""
    if ids := get_deleted_ids() - get_deprecated_ids():
        print("❌ The following rule IDs may have been deleted:")
        for id_ in ids:
            print(f"\t{id_}")
        raise typer.Exit(code=1)
    else:
        print("✅ No unaccounted deletions found! You're in the clear! 👍")


def remove(
    api_token: Optional[str] = typer.Option(
        None, help="Panther API token", envvar="PANTHER_API_TOKEN"
    ),
    api_host: Optional[str] = typer.Option(
        None, help="Panther API host", envvar="PANTHER_API_HOST"
    ),
):
    """Delete the entries listed in deprecated.txt"""

    ids = list(get_deprecated_ids())

    logging.basicConfig(
        format="[%(levelname)s][%(name)s]: %(message)s",
        level=logging.INFO,
    )

    return_code, out = pat_delete.run(
        backend=pat_util.get_api_backend(api_token, api_host),
        args=pat_delete.BulkDeleteArgs(analysis_id=ids, query_id=[], confirm=False),
    )

    if return_code == 1:
        if out:
            logging.error(out)
    elif return_code == 0:
        if out:
            logging.info(out)


def main():
    app = typer.Typer()
    app.command()(check)
    app.command()(remove)
    app()


if __name__ == "__main__":
    main()
