from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


def rule(event):
    return (event.get('eventName') == 'ConsoleLogin' and
            deep_get(event, 'userIdentity', 'type') == 'IAMUser' and
            deep_get(event, 'responseElements', 'ConsoleLogin') == 'Failure')


def title(event):
    return 'AWS logins failed in account [{}]'.format(
        lookup_aws_account_name(event.get('recipientAccountId')))
