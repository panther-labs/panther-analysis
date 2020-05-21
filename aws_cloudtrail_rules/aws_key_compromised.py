def rule(event):
    # Capture PutUserPolicy
    return event.get('eventName') == 'PutUserPolicy' and event['requestParameters'].get('policyName') == 'AWSExposedCredentialPolicy_DO_NOT_REMOVE'


def dedup(event):
    return event['userIdentity'].get('userName')


def title(event):
    return '{} {} key was uploaded to public github repo'.format(event['userIdentity'].get('accessKeyId'),dedup(event))