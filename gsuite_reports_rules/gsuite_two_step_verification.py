def rule(event):
    if event['id'].get('applicationName') != 'user_accounts':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == '2sv_change' and
                details.get('name') == '2sv_disable'):
            return True

    return False


def dedup(event):
    return event.get('actor', {}).get('email')


def title(event):
    return 'Two step verification was disabled for user [{}]'.format(
        event.get('actor', {}).get('email'))
