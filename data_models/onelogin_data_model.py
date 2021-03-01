import panther_event_type_helpers as event_type


def get_event_type(event):
    # currently, only tracking a handful of event types
    if event.get("event_type_id") == 72 and event.get("privilege_name") == "Super user":
        return event_type.ADMIN_ROLE_ASSIGNED
    if event.get("event_type_id") == 6:
        return event_type.FAILED_LOGIN
    if event.get("event_type_id") == 5:
        return event_type.SUCCESSFUL_LOGIN
    return None
