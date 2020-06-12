def rule(event):
    return (event.get('eventName') == 'PutUserPolicy' and
            event['requestParameters'].get(
                'policyName') == 'AWSExposedCredentialPolicy_DO_NOT_REMOVE')


def dedup(event):
    return event['userIdentity'].get('userName')


def title(event):
    message = '{username}\'s access key ID [{key}] was uploaded to a public GitHub repo'
    return message.format(username=dedup(event),
                          key=event['userIdentity'].get('accessKeyId'))
