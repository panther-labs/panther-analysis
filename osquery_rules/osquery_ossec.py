def rule(event):
    return 'ossec-rootkit' in event.get('name', '') and event.get('action') == 'added'


def title(event):
    return 'OSSEC rootkit found on [{}]'.format(event.get('hostIdentifier'))
