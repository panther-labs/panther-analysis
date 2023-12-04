import panther_event_type_helpers as event_type

ADMIN_EVENTS = {
    "business.add_admin",
    "business.invite_admin",
    "team.promote_maintainer",
}


def get_admin_role(event):
    action = event.get("action", "")
    return action if action in ADMIN_EVENTS else "<UNKNOWN_ADMIN_ROLE>"


def get_event_type(event):
    if event.get("action", "") in ADMIN_EVENTS:
        return event_type.ADMIN_ROLE_ASSIGNED
    if event.get("action", "") == "org.disable_two_factor_requirement":
        return event_type.MFA_DISABLED
    return None
