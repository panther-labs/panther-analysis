SECURITY_CONFIG_ACTIONS = [
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
]


def rule(event):
    if event['eventName'] == 'UpdateDetector':
        return not event['requestParameters'].get('enable', True)

    return event['eventName'] in SECURITY_CONFIG_ACTIONS
