from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and
            event['userIdentity'].get('type') == 'Root' and
            event.get('responseElements', {}).get('ConsoleLogin') == 'Failure')


def title(event):
    return 'AWS root login failed from [{ip}] in account [{account}]'.format(
        ip=event['sourceIPAddress'],
        account=lookup_aws_account_name(event.get('recipientAccountId')))
