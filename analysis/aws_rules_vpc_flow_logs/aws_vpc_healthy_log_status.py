def rule(event):
    return event['log-status'] == 'SKIPDATA'
