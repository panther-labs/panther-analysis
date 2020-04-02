def rule(event):
    return event.get('errorCode') == 'AccessDenied'


def dedup(event):
    return event.get('userIdentity', {}).get('arn')


def title(event):
    user_identity = event.get('userIdentity')
    return 'Access denied to {} {}'.format(user_identity.get('type'),
                                           user_identity.get('arn'))
