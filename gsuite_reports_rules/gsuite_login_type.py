from panther_base_helpers import gsuite_parameter_lookup as param_lookup

# Remove any unapproved login methods
APPROVED_LOGIN_TYPES = {
    'exchange',
    'google_password',
    'reauth',
    'saml',
    'unknown',
}


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'login' and
                details.get('name') != 'logout' and
                param_lookup(details.get('parameters', {}),
                             'login_type') not in APPROVED_LOGIN_TYPES):
            return True

    return False


def dedup(event):
    return event.get('actor', {}).get('email')


def title(event):
    return 'A login attempt of a non-approved type was detected for user [{}]'.format(
        event.get('actor', {}).get('email'))
