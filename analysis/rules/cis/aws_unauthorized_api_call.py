def rule(event):
    return event.get('errorCode') == 'AccessDenied'
