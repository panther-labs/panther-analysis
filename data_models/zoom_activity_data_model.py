import panther_event_type_helpers as event_type


def get_event_type(event):
    if event.get("type") == "Sign in":
        return event_type.SUCCESSFUL_LOGIN
    if event.get("type") == "Sign out":
        return event_type.LOGOUT
    return None
