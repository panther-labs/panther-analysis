def rule(event):
    return event['action'] == 'Blocked'


def title(event):
    return 'Access denied to domain ' + event['domain']
