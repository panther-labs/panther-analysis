import re

from panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION, ZENDESK_OWNER_CHANGED


def rule(event):
    if event.get("action", "") == "update" and event.get("source_type", "") == "account":
        matches = ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
        return bool(matches)
    return False


def title(event):
    old_owner = "<UNKNOWN_USER>"
    new_owner = "<UNKNOWN_USER>"
    matches = ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
    if matches:
        old_owner = matches.group("old_owner")
        new_owner = matches.group("new_owner")
    return f"zendesk administrative owner changed from {old_owner} to {new_owner}"
