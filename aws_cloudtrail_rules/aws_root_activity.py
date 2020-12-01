from panther import lookup_aws_account_name  # pylint: disable=import-error

EVENT_ALLOW_LIST = {'CreateServiceLinkedRole', 'ConsoleLogin'}


def rule(event):
    return (event['userIdentity'].get('type') == 'Root' and
            event.get('errorMessage') is None and
            event.get('userIdentity', {}).get('invokedBy') is None and
            event.get('eventType') != 'AwsServiceEvent' and
            event.get('eventName') not in EVENT_ALLOW_LIST)


def title(event):
    return 'AWS root activity detected from [{ip}] in account [{account}]'.format(
        ip=event.get('sourceIPAddress'),
        account=lookup_aws_account_name(event.get('recipientAccountId')))


def alert_context(event):
    return {
        'sourceIPAddress': event['sourceIPAddress'],
        'userIdentityAccountId': event['userIdentity']['accountId'],
        'userIdentityArn': event['userIdentity']['arn'],
        'eventTime': event['eventTime'],
        'mfaUsed': event.get('additionalEventData', {}).get('MFAUsed')
    }
