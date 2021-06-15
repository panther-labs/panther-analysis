import panther_event_type_helpers as event_type


def get_event_type(event):
    # user item being audited
    if event.get("source_type") == "user":
        # check for login events
        if event.get("action") == "login":
            return None
        # check for admin assignment
    return None
