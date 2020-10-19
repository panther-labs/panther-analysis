def rule(event):
    return event.get('event_type') == 'ACCESS_GRANTED'


def title(event):
    return 'User [{}] granted access to their account'.format(
        event.get('created_by', {}).get('name', '<UNKNOWN_USER>'))
