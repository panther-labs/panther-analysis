# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    'CreateTrail',
    'UpdateTrail',
    'StartLogging',
}


def rule(event):
    return event['eventName'] in CLOUDTRAIL_CREATE_UPDATE


def title(event):
    return 'CloudTrail [{}] was created/updated'.format(
        event['requestParameters'].get('name'))
