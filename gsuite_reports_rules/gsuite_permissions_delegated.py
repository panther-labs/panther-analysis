def rule(event):
    if event['id'].get('applicationName') != 'admin':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'DELEGATED_ADMIN_SETTINGS' and
                details.get('name') == 'ASSIGN_ROLE'):
            return True

    return False


def dedup(event):
    return event.get('actor', {}).get('email')


def title(event):
    return 'User [{}] was delegated new administrator privileges'.format(
        event.get('actor', {}).get('email'))
