def rule(event):
    if event['id'].get('applicationName') != 'drive':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'acl_change' and
                details.get('visibility_change') == 'external'):
            return True

    return False


def dedup(event):
    return event['p_row_id']


def title(event):
    return 'User [{}] made a document externally visible for the first time'.format(
        event.get('actor', {}).get('email'))
