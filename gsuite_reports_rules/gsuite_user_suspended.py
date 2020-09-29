USER_SUSPENDED_EVENTS = {
    'account_disabled_generic',
    'account_disabled_spamming_through_relay',
    'account_disabled_spamming',
    'account_disabled_hijacked',
}


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'account_warning' and
                details.get('name') in USER_SUSPENDED_EVENTS):
            return True

    return False


def title(event):
    return 'User [{}]\'s account was disabled'.format(
        event.get('actor', {}).get('email'))
