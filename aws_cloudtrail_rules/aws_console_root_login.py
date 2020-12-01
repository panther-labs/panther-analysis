from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and
            event['userIdentity'].get('type') == 'Root' and
            event.get('responseElements', {}).get('ConsoleLogin') == 'Success')


def title(event):
    return 'AWS root login detected from [{ip}] in account [{account}]'.format(
        ip=event['sourceIPAddress'],
        account=lookup_aws_account_name(event.get('recipientAccountId')))


def dedup(event):
    # Each Root login should generate a unique alert
    return '-'.join(
        [event['recipientAccountId'], event['eventName'], event['eventTime']])


def alert_context(event):
    return {
        'sourceIPAddress': event['sourceIPAddress'],
        'userIdentityAccountId': event['userIdentity']['accountId'],
        'userIdentityArn': event['userIdentity']['arn'],
        'eventTime': event['eventTime'],
        'mfaUsed': event.get('additionalEventData', {}).get('MFAUsed')
    }
