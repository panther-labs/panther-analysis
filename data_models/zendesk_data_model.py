import re

import panther_event_type_helpers as event_type

ADMIN_ROLE_ASSIGNED = r"Role changed from (?P<old_role>.+) to (?P<new_role>[^$]+)"
LOGIN_EVENT = (
    r"(?P<login_result>[\S]+) sign-in using (?P<authentication_method>.+) from (?P<authentication_location>[^$]+)"
)
TWO_FACTOR_SOURCE = f"Two-Factor authentication for all admins and agents"

## key names
CHANGE_DESCRIPTION = "changes_description"

def get_event_type(event):
    # user related events
    if event.get("source_type") == "user":
        # check for login events
        if event.get("action") == "login":
            matches = re.match(LOGIN_EVENT, event.get(CHANGE_DESCRIPTION, ""), re.IGNORECASE)
            if matches:
                if matches.group("login_result").lower().startswith("success"):
                    return event_type.SUCCESSFUL_LOGIN
            return event_type.FAILED_LOGIN
        # check for admin assignment
        if event.get("action") == "update":
            if bool(re.match(ADMIN_ROLE_ASSIGNED, event.get(CHANGE_DESCRIPTION, ""), re.IGNORECASE)):
                return event_type.ADMIN_ROLE_ASSIGNED
    
    # account related events
    if event.get("source_type", "") == "account_setting":
        matches = re.match(TWO_FACTOR_SOURCE, event.get("source_label", ""))
        if matches:
            if event.get(CHANGE_DESCRIPTION, "").lower() == "disabled":
                return event_type.MFA_DISABLED
    
    return None


def get_assigned_admin_role(event):
    matches = re.search(ADMIN_ROLE_ASSIGNED, event.get(CHANGE_DESCRIPTION,""), re.IGNORECASE)
    if matches:
        return matches.group("new_role")
    return None


def get_authentication_method(event):
    matches = re.search(LOGIN_EVENT, event.get(CHANGE_DESCRIPTION, ""), re.IGNORECASE)
    if matches:
        return matches.group("authentication_method")
    return None


def get_original_admin_role(event):
    matches = re.search(ADMIN_ROLE_ASSIGNED, event.get(CHANGE_DESCRIPTION, ""), re.IGNORECASE)
    if matches:
        return matches.group("old_role")
    return None


def get_user(event):
    # some events will have the user in the source_label field,
    # otherwise we might not konw who the user is
    if event.get("source_type", "").lower() == "user":
        return event.get("source_label")
    return "<UNKNOWN_USER>"
