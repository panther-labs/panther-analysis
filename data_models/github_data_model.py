import panther_event_type_helpers as event_type


def get_admin_role(_):
    # github doesn't record the admin role in the event
    return "<UNKNOWN_ROLE>"


def get_event_type(event):
    if event.get("action") == "team.promote_maintainer":
        return event_type.ADMIN_ROLE_ASSIGNED
    return None
