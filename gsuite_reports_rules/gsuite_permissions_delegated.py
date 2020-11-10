from panther_base_helpers import gsuite_details_lookup as details_lookup  # pylint: disable=import-error
from panther_base_helpers import gsuite_parameter_lookup as param_lookup  # pylint: disable=import-error


def rule(event):
    if event['id'].get('applicationName') != 'admin':
        return False

    return bool(details_lookup('DELEGATED_ADMIN_SETTINGS', ['ASSIGN_ROLE'], event))


def title(event):
    details = details_lookup('DELEGATED_ADMIN_SETTINGS', ['ASSIGN_ROLE'], event)
    role = param_lookup(details.get('parameters', {}), 'ROLE_NAME')
    user = param_lookup(details.get('parameters', {}), 'USER_EMAIL')
    if not role:
        role = '<UNKNOWN_ROLE>'
    if not user:
        user = '<UKNNOWN_USER>'
    return 'User [{}] delegated new administrator privileges [{}] to [{}]'.format(
        event.get('actor', {}).get('email'), role, user)
