UPDATE_EVENTS = {
    'ChangePassword', 'CreateAccessKey', 'CreateLoginProfile', 'CreateUser'
}


def rule(event):
    return event.get('eventName') in UPDATE_EVENTS


def dedup(event):
    return event.get('userIdentity', {}).get('userName')


def title(event):
    user_identity = event.get('userIdentity', {})
    return '{} {} updated IAM credentials'.format(user_identity.get('type'),
                                                  user_identity.get('arn'))
