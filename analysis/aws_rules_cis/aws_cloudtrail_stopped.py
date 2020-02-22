# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    'DeleteTrail',
    'StopLogging',
}


def rule(event):
    return event.get('eventName') in CLOUDTRAIL_STOP_DELETE
