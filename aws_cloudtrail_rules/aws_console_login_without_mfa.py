from panther import lookup_aws_account_name  # pylint: disable=import-error


def rule(event):
    if event['eventName'] != 'ConsoleLogin':
        return False

    additional_event_data = event.get('additionalEventData', {})
    session_context = event.get('userIdentity', {}).get('sessionContext', {})
    response_elements = event.get('responseElements', {})

    return (
        # Only alert on successful logins
        response_elements.get('ConsoleLogin') == 'Success' and
        # Where MFA is not in use
        additional_event_data.get('MFAUsed') == 'No' and
        # Ignoring SSO login events
        not additional_event_data.get('SamlProviderArn') and
        # And ignoring logins that were authenticated via a session that was itself
        # authenticated with MFA
        session_context.get('attributes', {}).get('mfaAuthenticated') != 'true')


def title(event):
    return 'AWS logins detected without MFA in account [{}]'.format(
        lookup_aws_account_name(event.get('recipientAccountId')))
