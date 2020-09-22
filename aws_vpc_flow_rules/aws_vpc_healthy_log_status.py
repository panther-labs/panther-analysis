def rule(event):
    return event.get('log-status') == 'SKIPDATA'
