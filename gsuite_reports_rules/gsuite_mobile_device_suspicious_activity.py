from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, 'id', 'applicationName') != 'mobile':
        return False

    return bool(
        details_lookup('suspicious_activity', ['SUSPICIOUS_ACTIVITY_EVENT'],
                       event))


def title(event):
    return 'User [{}]\'s device was compromised'.format(
        deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>'))
