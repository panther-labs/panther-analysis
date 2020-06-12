from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and
            event['userIdentity'].get('type') == 'Root' and
            event.get('responseElements', {}).get('ConsoleLogin') == 'Success')


def dedup(event):
    return '{ip}-{account}'.format(ip=event['sourceIPAddress'],
                                   account=event['recipientAccountId'])


def title(event):
    return 'AWS root login detected from [{ip}] in account [{account}]'.format(
        ip=event['sourceIPAddress'],
        account=lookup_aws_account_name(event['recipientAccountId']))
