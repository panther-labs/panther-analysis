def rule(event):
    # Capture PutUserPolicy
    request = event.get('requestParameters')
    return event.get('eventName').startswith(
        'PutUserPolicy') and request.get('policyName').startswith('AWSExposedCredentialPolicy_DO_NOT_REMOVE')


def dedup(event):
    return event.get('userIdentity', {}).get('userName')


def title(event):
    user_identity = event.get('userIdentity', {})
    return '{} {} key was uploaded to public github repo'.format(user_identity.get('accessKeyId'),dedup(event))