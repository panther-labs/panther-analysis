import logging
import re

import panther_event_type_helpers as event_type
from panther_base_helpers import (
    ZENDESK_APP_ROLE_ASSIGNED,
    ZENDESK_CHANGE_DESCRIPTION,
    ZENDESK_LOGIN_EVENT,
    ZENDESK_ROLE_ASSIGNED,
    ZENDESK_TWO_FACTOR_SOURCES,
    zendesk_get_roles,
)


def get_event_type(event):
    # user related events
    if event.get("source_type", "") == "user":
        # check for login events
        if event.get("action") == "login":
            matches = ZENDESK_LOGIN_EVENT.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
            if matches:
                if matches.group("login_result").lower().startswith("success"):
                    return event_type.SUCCESSFUL_LOGIN
            return event_type.FAILED_LOGIN
        # check for admin assignment
        if event.get("action") == "update":
            role_change = event.get(ZENDESK_CHANGE_DESCRIPTION, "")
            if ("\n") in role_change:
                for app_change in role_change.split("\n"):
                    matches = ZENDESK_APP_ROLE_ASSIGNED.match(app_change)
                    if matches:
                        for admin in {"admin", "account owner"}:
                            if admin in matches.group("new_role").lower():
                                return event_type.ADMIN_ROLE_ASSIGNED
            else:
                matches = ZENDESK_ROLE_ASSIGNED.match(role_change)
                if matches:
                    for admin in {"admin", "account owner"}:
                        if admin in matches.group("new_role").lower():
                            return event_type.ADMIN_ROLE_ASSIGNED
        return None
    # account related events
    if event.get("source_type", "") == "account_setting":
        if event.get("source_label", "") in ZENDESK_TWO_FACTOR_SOURCES:
            if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
                return event_type.MFA_DISABLED

    return None


def get_assigned_admin_role(event):
    _, new_role = zendesk_get_roles(event)
    for admin in {"admin", "account owner"}:
        if admin in new_role.lower():
            return new_role
    return None


def get_user(event):
    # some events will have the user in the source_label field,
    # otherwise the user field may not be relevant
    if event.get("source_type", "").lower() == "user":
        return event.get("source_label")
    return "<UNKNOWN_USER>"
