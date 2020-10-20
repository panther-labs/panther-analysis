def rule(event):
    # DEVICE_TRUST_CHECK_FAILED
    #  detect when a user attempts to login from an untrusted device
    return event.get('event_type') == 'DEVICE_TRUST_CHECK_FAILED'


def title(event):
    return 'User [{}] attempted to login from an untrusted device.'.format(
        event.get('created_by', {}).get('name', "<UNKNOWN_USER>"))
