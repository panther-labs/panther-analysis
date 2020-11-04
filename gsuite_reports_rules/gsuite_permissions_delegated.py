from panther_base_helpers import gsuite_parameter_lookup as param_lookup

def rule(event):
    if event['id'].get('applicationName') != 'admin':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'DELEGATED_ADMIN_SETTINGS' and
                details.get('name') == 'ASSIGN_ROLE'):
            return True

    return False


def title(event):
    role = '<UNKNOWN_ROLE>'
    user = '<UKNNOWN_USER>'
    for details in event.get('events', [{}]):
        if (details.get('type') == 'DELEGATED_ADMIN_SETTINGS' and
                details.get('name') == 'ASSIGN_ROLE'):
            role = param_lookup(details.get('parameters', {}), 'ROLE_NAME')
            user = param_lookup(details.get('parameters', {}), 'USER_EMAIL')
            break
    return 'User [{}] delegated new administrator privileges [{}] to [{}]'.format(
        event.get('actor', {}).get('email'), role, user)
