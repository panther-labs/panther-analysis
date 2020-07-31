RESOURCE_CHANGE_EVENTS = {
    'create',
    'move',
    'upload',
    'edit',
}

PERMISSIVE_VISIBILITY = {
    'people_with_link',
    'public_on_the_web',
}


def rule(event):
    if event['id'].get('applicationName') != 'drive':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'access' and
                details.get('name') in RESOURCE_CHANGE_EVENTS and
                details.get('visibility') in PERMISSIVE_VISIBILITY):
            return True

    return False


def dedup(event):
    return event['p_row_id']


def title(event):
    return 'User [{}] modified a document that has overly permissive share settings'.format(
        event.get('actor', {}).get('email'))
