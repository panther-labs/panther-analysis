def rule(event):
    # ADD_LOGIN_ACTIVITY_DEVICE
    #  detect when a user logs in from a device not previously seen
    return event.get('event_type') == 'ADD_LOGIN_ACTIVITY_DEVICE'


def title(event):
    return 'User [{}] logged in from a new device.'.format(
        event.get('created_by', {}).get('name', "<UNKNOWN_USER>"))
