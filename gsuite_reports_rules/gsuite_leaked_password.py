from panther_base_helpers import gsuite_details_lookup as details_lookup  # pylint: disable=import-error
from panther_base_helpers import gsuite_parameter_lookup as param_lookup  # pylint: disable=import-error


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    return bool(
        details_lookup('account_warning', ['account_disabled_password_leak'],
                       event))


def title(event):
    details = details_lookup('account_warning',
                             ['account_disabled_password_leak'], event)
    user = param_lookup(details.get('paramters', {}), 'affected_email_address')
    if not user:
        user = '<UNKNOWN_USER>'
    return 'User [{}]\'s account was disabled due to a password leak'.format(
        user)
