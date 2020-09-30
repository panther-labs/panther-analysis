def rule(event):
    return 'ossec-rootkit' in event['name'] and event['action'] == 'added'


def title(event):
    return 'OSSEC rootkit found on [{}]'.format(event.get('hostIdentifier'))
