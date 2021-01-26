from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup
from panther_base_helpers import deep_get

PASSWORD_LEAKED_EVENTS = {
    'account_disabled_password_leak',
}


def rule(event):
    if deep_get(event, 'id', 'applicationName') != 'login':
        return False

    return bool(details_lookup('account_warning', PASSWORD_LEAKED_EVENTS,
                               event))


def title(event):
    details = details_lookup('account_warning', PASSWORD_LEAKED_EVENTS, event)
    user = param_lookup(details.get('parameters', {}), 'affected_email_address')
    if not user:
        user = '<UNKNOWN_USER>'
    return 'User [{}]\'s account was disabled due to a password leak'.format(
        user)
