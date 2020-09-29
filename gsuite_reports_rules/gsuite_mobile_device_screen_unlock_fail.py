from panther_base_helpers import gsuite_parameter_lookup as param_lookup

MAX_UNLOCK_ATTEMPTS = 10


def rule(event):
    if event['id'].get('applicationName') != 'mobile':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'suspicious_activity' and
                details.get('name') == 'FAILED_PASSWORD_ATTEMPTS_EVENT' and int(
                    param_lookup(details.get('parameters', {}),
                                 'FAILED_PASSWD_ATTEMPTS')) >
                MAX_UNLOCK_ATTEMPTS):
            return True

    return False


def title(event):
    return 'User [{}]\'s device had multiple failed unlock attempts'.format(
        event.get('actor', {}).get('email'))
