def rule(event):
    return event.get('event_type') == 'FAILED_LOGIN'


def title(event):
    return 'User [{}] has exceeded the failed login threshold.'.format(
        event.get('source', {}).get('name', "<UNKNOWN_USER>"))
