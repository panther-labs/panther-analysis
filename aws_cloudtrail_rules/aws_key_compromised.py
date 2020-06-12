EXPOSED_CRED_POLICY = 'AWSExposedCredentialPolicy_DO_NOT_REMOVE'


def rule(event):
    request_params = event.get('requestParameters', {})
    return (event['eventName'] == 'PutUserPolicy' and
            request_params.get('policyName') == EXPOSED_CRED_POLICY)


def dedup(event):
    return event['userIdentity'].get('userName')


def title(event):
    message = '{username}\'s access key ID [{key}] was uploaded to a public GitHub repo'
    return message.format(username=dedup(event),
                          key=event['userIdentity'].get('accessKeyId'))
