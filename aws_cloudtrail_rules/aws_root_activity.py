from panther import lookup_aws_account_name  # pylint: disable=import-error

EVENT_ALLOW_LIST = {'CreateServiceLinkedRole', 'ConsoleLogin'}


def rule(event):
    return (event['userIdentity'].get('type') == 'Root' and
            event.get('errorMessage') is None and
            event['userIdentity'].get('invokedBy') is None and
            event['eventType'] != 'AwsServiceEvent' and
            event['eventName'] not in EVENT_ALLOW_LIST)


def title(event):
    return 'AWS root activity detected from [{ip}] in account [{account}]'.format(
        ip=event['sourceIPAddress'],
        account=lookup_aws_account_name(event.get('recipientAccountId')))
