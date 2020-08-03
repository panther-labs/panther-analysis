def rule(event):
    if event['id'].get('applicationName') != 'access_transparency':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'GSUITE_RESOURCE' and
                details.get('name') == 'ACCESS'):
            return True

    return False
