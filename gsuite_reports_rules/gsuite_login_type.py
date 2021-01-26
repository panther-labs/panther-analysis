from panther_base_helpers import gsuite_parameter_lookup as param_lookup
from panther_base_helpers import deep_get

# Remove any unapproved login methods
APPROVED_LOGIN_TYPES = {
    'exchange',
    'google_password',
    'reauth',
    'saml',
    'unknown',
}


def rule(event):
    if deep_get(event, 'id', 'applicationName') != 'login':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'login' and
                details.get('name') != 'logout' and
                param_lookup(details.get('parameters', {}),
                             'login_type') not in APPROVED_LOGIN_TYPES):
            return True

    return False


def title(event):
    return 'A login attempt of a non-approved type was detected for user [{}]'.format(
        deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>'))
