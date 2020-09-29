SUSPICOUS_LOGIN_TYPES = {
    'suspicious_login',
    'suspicious_login_less_secure_app',
    'suspicious_programmatic_login',
}


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'account_warning' and
                details.get('name') in SUSPICOUS_LOGIN_TYPES):
            return True

    return False


def title(event):
    return 'A suspicious login was reported for user [{}]'.format(
        event.get('actor', {}).get('email'))
