from panther import lookup_aws_account_name  # pylint: disable=import-error
from panther_base_helpers import deep_get

EVENT_ALLOW_LIST = {'CreateServiceLinkedRole', 'ConsoleLogin'}


def rule(event):
    return (deep_get(event, 'userIdentity', 'type') == 'Root' and
            event.get('errorMessage') is None and
            deep_get(event, 'userIdentity', 'invokedBy') is None and
            event.get('eventType') != 'AwsServiceEvent' and
            event.get('eventName') not in EVENT_ALLOW_LIST)


def title(event):
    return 'AWS root activity detected from [{ip}] in account [{account}]'.format(
        ip=event.get('sourceIPAddress'),
        account=lookup_aws_account_name(event.get('recipientAccountId')))


def alert_context(event):
    return {
        'sourceIPAddress': event['sourceIPAddress'],
        'userIdentityAccountId': deep_get(event, 'userIdentity', 'accountId'),
        'userIdentityArn': deep_get(event, 'userIdentity', 'arn'),
        'eventTime': event['eventTime'],
        'mfaUsed': deep_get(event, 'additionalEventData', 'MFAUsed')
    }
