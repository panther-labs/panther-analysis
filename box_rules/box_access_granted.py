from panther_base_helpers import deep_get


def rule(event):
    return event.get('event_type') == 'ACCESS_GRANTED'


def title(event):
    return 'User [{}] granted access to their account'.format(
        deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>'))
