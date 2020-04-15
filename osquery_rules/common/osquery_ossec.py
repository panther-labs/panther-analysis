def rule(event):
    return 'ossec-rootkit' in event['name'] and event['action'] == 'added'


def dedup(event):
    return event.get('hostIdentifier')


def title(event):
    return 'OSSEC rootkit found on {}'.format(event.get('hostIdentifier'))
