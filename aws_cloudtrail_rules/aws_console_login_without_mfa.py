from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and event.get(
        'responseElements', {}).get('ConsoleLogin') == 'Success' and
            event.get('additionalEventData', {}).get('MFAUsed') == 'No')


def dedup(event):
    return event['recipientAccountId']


def title(event):
    return 'AWS logins detected without MFA in account [{}]'.format(
        lookup_aws_account_name(event['recipientAccountId']))
