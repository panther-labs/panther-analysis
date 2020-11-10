from panther_base_helpers import gsuite_details_lookup as details_lookup  # pylint: disable=import-error
from panther_base_helpers import gsuite_parameter_lookup as param_lookup  # pylint: disable=import-error

SUSPICOUS_LOGIN_TYPES = {
    'suspicious_login',
    'suspicious_login_less_secure_app',
    'suspicious_programmatic_login',
}


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    return bool(details_lookup('account_warning', SUSPICOUS_LOGIN_TYPES, event))


def title(event):
    details = details_lookup('account_warning', SUSPICOUS_LOGIN_TYPES, event)
    user = param_lookup(details.get('parameters', {}), 'affected_email_address')
    if not user:
        user = '<UNKNOWN_USER>'
    return 'A suspicious login was reported for user [{}]'.format(user)
