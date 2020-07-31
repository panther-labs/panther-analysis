MAX_UNLOCK_ATTEMPTS = 10


def rule(event):
    if event['id'].get('applicationName') != 'mobile':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'suspicious_activity' and
                details.get('name') == 'FAILED_PASSWORD_ATTEMPTS_EVENT' and
                details.get('parameters', {}).get('FAILED_PASSWD_ATTEMPTS') >
                MAX_UNLOCK_ATTEMPTS):
            return True

    return False


def dedup(event):
    return event.get('actor', {}).get('email')


def title(event):
    return 'User [{}]\'s device had multiple failed unlock attempts'.format(
        event.get('actor', {}).get('email'))
