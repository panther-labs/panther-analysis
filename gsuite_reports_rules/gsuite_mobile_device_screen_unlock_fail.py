from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

MAX_UNLOCK_ATTEMPTS = 10


def rule(event):
    if event['id'].get('applicationName') != 'mobile':
        return False

    details = details_lookup('suspicious_activity',
                             ['FAILED_PASSWORD_ATTEMPTS_EVENT'], event)
    return bool(details) and int(
        param_lookup(details.get('parameters', {}),
                     'FAILED_PASSWD_ATTEMPTS')) > MAX_UNLOCK_ATTEMPTS


def title(event):
    return 'User [{}]\'s device had multiple failed unlock attempts'.format(
        event.get('actor', {}).get('email'))
