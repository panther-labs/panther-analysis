def rule(event):
    return event['action'] == 'Blocked'


def dedup(event):
    return event['domain']


def title(event):
    return 'Access denied to domain ' + event['domain']
