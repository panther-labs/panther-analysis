def rule(event):
    if event['id'].get('applicationName') != 'mobile':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'suspicious_activity' and
                details.get('name') == 'SUSPICIOUS_ACTIVITY_EVENT'):
            return True

    return False


def dedup(event):
    return event.get('actor', {}).get('email')


def title(event):
    return 'User [{}]\'s device was compromised'.format(
        event.get('actor', {}).get('email'))
