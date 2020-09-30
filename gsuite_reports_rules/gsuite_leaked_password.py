def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'account_warning' and
                details.get('name') == 'account_disabled_password_leak'):
            return True

    return False


def title(event):
    return 'User [{}]\'s account was disabled due to a password leak'.format(
        event.get('actor', {}).get('email'))
