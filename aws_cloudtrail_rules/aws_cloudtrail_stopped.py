from panther import lookup_aws_account_name  # pylint: disable=import-error

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    'DeleteTrail',
    'StopLogging',
}


def rule(event):
    return event['eventName'] in CLOUDTRAIL_STOP_DELETE


def dedup(event):
    # Merge on the CloudTrail ARN
    return event['requestParameters'].get('name')


def title(event):
    trail_arn = event['requestParameters'].get('name')
    if event['eventName'] == 'DeleteTrail':
        action = 'deleted'
    elif event['eventName'] == 'StopLogging':
        action = 'stopped'
    return 'CloudTrail [{}] in account [{}] has been {}'.format(
        trail_arn, lookup_aws_account_name(event['recipientAccountId']), action)
