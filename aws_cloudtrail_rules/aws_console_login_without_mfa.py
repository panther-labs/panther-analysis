from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    if event['eventName'] != 'ConsoleLogin':
        return False

    additional_event_data = event.get('additionalEventData', {})
    response_elements = event.get('responseElements', {})

    return (response_elements.get('ConsoleLogin') == 'Success' and
            additional_event_data.get('MFAUsed') == 'No' and
            # Ignore SSO login events
            not additional_event_data.get('SamlProviderArn'))


def dedup(event):
    return event['recipientAccountId']


def title(event):
    return 'AWS logins detected without MFA in account [{}]'.format(
        lookup_aws_account_name(event['recipientAccountId']))
