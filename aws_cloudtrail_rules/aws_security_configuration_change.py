SECURITY_CONFIG_ACTIONS = {
    'DeleteAccountPublicAccessBlock',
    'DeleteDeliveryChannel',
    'DeleteDetector',
    'DeleteFlowLogs',
    'DeleteRule',
    'DeleteTrail',
    'DisableEbsEncryptionByDefault',
    'DisableRule',
    'StopConfigurationRecorder',
    'StopLogging',
}


def rule(event):
    if event['eventName'] == 'UpdateDetector':
        return not event['requestParameters'].get('enable', True)

    return event['eventName'] in SECURITY_CONFIG_ACTIONS


def title(event):
    user = event['userIdentity'].get('userName') or event['userIdentity'].get(
        'sessionContext').get('sessionIssuer').get('userName')

    return f"Sensitive AWS API call {event['eventName']} made by {user}"
