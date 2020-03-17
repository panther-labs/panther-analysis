UPDATE_EVENTS = {
    'ChangePassword', 'CreateAccessKey', 'CreateLoginProfile', 'CreateUser'
}

def rule(event):
    return event.get('eventName') in UPDATE_EVENTS

def dedup(event):
    return event.get('userIdentity', {}).get('userName')
