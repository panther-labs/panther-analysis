import re

from panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION

ZENDESK_OWNER_CHANGED = re.compile(
    r"Owner changed from (?P<old_owner>.+) to (?P<new_owner>[^$]+)", re.IGNORECASE
)


def rule(event):
    if event.get("action", "") == "update" and event.get("source_type", "") == "account":
        return event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("owner changed from ")
    return False


def title(event):
    old_owner = "<UNKNOWN_USER>"
    new_owner = "<UNKNOWN_USER>"
    matches = ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
    if matches:
        old_owner = matches.group("old_owner")
        new_owner = matches.group("new_owner")
    return f"zendesk administrative owner changed from {old_owner} to {new_owner}"
