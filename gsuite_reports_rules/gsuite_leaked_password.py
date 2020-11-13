from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

PASSWORD_LEAKED_EVENTS = {
    'account_disabled_password_leak',
}


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    return bool(details_lookup('account_warning', PASSWORD_LEAKED_EVENTS,
                               event))


def title(event):
    details = details_lookup('account_warning', PASSWORD_LEAKED_EVENTS, event)
    user = param_lookup(details.get('paramters', {}), 'affected_email_address')
    if not user:
        user = '<UNKNOWN_USER>'
    return 'User [{}]\'s account was disabled due to a password leak'.format(
        user)
