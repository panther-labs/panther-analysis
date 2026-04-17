def rule(event):
    # ADD_LOGIN_ACTIVITY_DEVICE
    #  detect when a user logs in from a device not previously seen
    return event.get("event_type") == "ADD_LOGIN_ACTIVITY_DEVICE"


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] "
        f"logged in from a new device."
    )
