# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CHANGE_EVENTS = {
    'CreateTrail',
    'UpdateTrail',
    'DeleteTrail',
    'StartLogging',
    'StopLogging',
}


def rule(event):
    return event.get('eventName') in CLOUDTRAIL_CHANGE_EVENTS
