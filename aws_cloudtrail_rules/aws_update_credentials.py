UPDATE_EVENTS = {
    'ChangePassword', 'CreateAccessKey', 'CreateLoginProfile', 'CreateUser'
}


def rule(event):
    return event.get(
        'eventName') in UPDATE_EVENTS and not event.get('errorCode')


def dedup(event):
    return event['userIdentity'].get('userName')


def title(event):
    user_identity = event['userIdentity']
    return '{} [{}] has updated their IAM credentials'.format(
        user_identity.get('type'), user_identity.get('arn'))
