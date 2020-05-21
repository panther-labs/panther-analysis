# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_CREATE_EVENTS = {
    'PutDeliveryChannel',
    'PutConfigurationRecorder',
    'StartConfigurationRecorder',
}


def rule(event):
    return event['eventName'] in CONFIG_SERVICE_CREATE_EVENTS
