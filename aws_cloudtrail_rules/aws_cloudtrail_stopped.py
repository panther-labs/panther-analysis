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
    return 'CloudTrail [{}] in account [{}] was stopped/deleted'.format(
        dedup(event), lookup_aws_account_name(event['recipientAccountId']))
