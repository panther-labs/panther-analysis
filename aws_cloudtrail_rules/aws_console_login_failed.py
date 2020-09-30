from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    return (event['eventName'] == 'ConsoleLogin' and
            event['userIdentity'].get('type') == 'IAMUser' and
            event.get('responseElements', {}).get('ConsoleLogin') == 'Failure')


def title(event):
    return 'AWS logins failed in account [{}]'.format(
        lookup_aws_account_name(event.get('recipientAccountId')))
