import panther_event_type_helpers as event_type

ADMIN_EVENTS = {
    "business.add_admin",
    "business.invite_admin",
    "team.promote_maintainer",
}

CONDITIONAL_ADMIN_EVENTS = {
    "team.add_repository",
}


def get_admin_role(event):
    action = event.get("action", "")
    permission = event.get("permission", "")
    if action in CONDITIONAL_ADMIN_EVENTS and permission == "admin":
        return action
    return action if action in ADMIN_EVENTS else "<UNKNOWN_ADMIN_ROLE>"


def get_event_type(event):
    action = event.get("action", "")
    permission = event.get("permission", "")
    if action in ADMIN_EVENTS:
        return event_type.ADMIN_ROLE_ASSIGNED
    if action in CONDITIONAL_ADMIN_EVENTS and permission == "admin":
        return event_type.ADMIN_ROLE_ASSIGNED
    if event.get("action", "") == "org.disable_two_factor_requirement":
        return event_type.MFA_DISABLED
    return None
