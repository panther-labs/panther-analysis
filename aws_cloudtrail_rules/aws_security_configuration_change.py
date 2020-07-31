SECURITY_CONFIG_ACTIONS = [
    'DeleteFlowLogs',
    'DeleteTrail',
    'UpdateTrail',
    'StopLogging',
    'DeleteDeliveryChannel',
    'StopConfigurationRecorder',
    'DeleteRule',
    'DisableRule',
    'DeleteDetector',
    'DeleteAccountPublicAccessBlock',
    'DisableEbsEncryptionByDefault',
]


def rule(event):
    if event['eventName'] == 'UpdateDetector':
        return not event['requestParameters'].get('enable', True)

    return event['eventName'] in SECURITY_CONFIG_ACTIONS
