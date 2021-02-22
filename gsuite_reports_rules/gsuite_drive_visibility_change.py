from panther_base_helpers import gsuite_parameter_lookup as param_lookup
from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, 'id', 'applicationName') != 'drive':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'acl_change' and
                param_lookup(details.get('parameters', {}),
                             'visibility_change') == 'external'):
            return True

    return False


def dedup(event):
    return deep_get(event, 'actor', 'email')


def title(event):
    events = event.get('events', [{}])
    actor_email = deep_get(event, 'actor', 'email', default='EMAIL_UNKNOWN')
    target_user_email = 'EMAIL_UNKNOWN'
    doc_title = 'UNKNOWN_TITLE'
    for detail in events:
        if detail.get('type') == 'acl_change':
            if param_lookup(detail.get('parameters', {}), 'doc_title'):
                doc_title = param_lookup(detail.get('parameters', {}),
                                         'doc_title')
            if param_lookup(detail.get('parameters', {}), 'target_user'):
                target_user_email = param_lookup(detail.get('parameters', {}),
                                                 'target_user')
            break
    return 'User [{}] made a document [{}] externally visible for the first time with [{}]'.format(
        actor_email, doc_title, target_user_email)
