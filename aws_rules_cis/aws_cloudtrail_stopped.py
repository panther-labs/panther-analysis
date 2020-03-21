# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    'DeleteTrail',
    'StopLogging',
}


def rule(event):
    return event.get('eventName') in CLOUDTRAIL_STOP_DELETE


def dedup(event):
    # Merge on the specific CloudTrail
    return event['requestParameters'].get('name')


def title(event):
    trail_arn = event['requestParameters'].get('name')
    return 'CloudTrail {} Has Been Disabled with {}'.format(
        trail_arn, event.get('eventName'))
