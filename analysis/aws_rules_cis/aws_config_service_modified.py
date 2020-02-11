# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_MODIFIED_EVENTS = {
    'StopConfigurationRecorder',
    'DeleteDeliveryChannel',
    'PutDeliveryChannel',
    'PutConfigurationRecorder',
}


def rule(event):
    return event['eventName'] in CONFIG_SERVICE_MODIFIED_EVENTS
