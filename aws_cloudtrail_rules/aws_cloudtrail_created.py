# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    'CreateTrail',
    'UpdateTrail',
    'StartLogging',
}


def rule(event):
    return event['eventName'] in CLOUDTRAIL_CREATE_UPDATE
