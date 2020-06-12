from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    additional_event_data = event.get('additionalEventData', {})
    return (event['eventName'] == 'ConsoleLogin' and
            event['userIdentity'].get('type') != 'AssumedRole' and
            not additional_event_data.get('SamlProviderArn'))


def dedup(event):
    return event.get('recipientAccountId')


def title(event):
    return 'AWS logins without SAML in account [{}]'.format(
        lookup_aws_account_name(event.get('recipientAccountId')))
