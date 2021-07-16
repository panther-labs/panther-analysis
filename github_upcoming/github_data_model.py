import panther_event_type_helpers as event_type


def get_admin_role(_):
    # github doesn't record the admin role in the event
    return "<UNKNOWN_ROLE>"


def get_event_type(event):
    if event.get("action") == "team.promote_maintainer":
        return event_type.ADMIN_ROLE_ASSIGNED
    if event.get("action") == "org.disable_two_factor_requirement":
        return event_type.MFA_DISABLED
    return None
