def rule(event):
    return event.get('event_type') == 'FAILED_LOGIN'


def title(event):
    return 'User [{}] has exceeded the failed logins threshold.'.format(
        event.get('created_by', {}).get('name', "<UNKNOWN_USER>"))
