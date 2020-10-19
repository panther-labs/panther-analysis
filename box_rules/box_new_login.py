def rule(event):
    return (event.get('event_type') == 'ADD_LOGIN_ACTIVITY_DEVICE' or
            event.get('event_type') == 'DEVICE_TRUST_CHECK_FAILED	')


def title(event):
    return 'User [{}] logged in from a new device.'.format(
        event.get('created_by', {}).get('name', "<UNKNOWN_USER>"))
