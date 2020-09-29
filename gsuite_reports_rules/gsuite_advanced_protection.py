def rule(event):
    if event['id'].get('applicationName') != 'user_accounts':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'titanium_change' and
                details.get('name') == 'titanium_unenroll'):
            return True

    return False


def title(event):
    return 'Advanced protection was disabled for user [{}]'.format(
        event.get('actor', {}).get('email'))
