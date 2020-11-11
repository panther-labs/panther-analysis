from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

RESOURCE_CHANGE_EVENTS = {
    'create',
    'move',
    'upload',
    'edit',
}

PERMISSIVE_VISIBILITY = {
    'people_with_link',
    'public_on_the_web',
}


def rule(event):
    if event['id'].get('applicationName') != 'drive':
        return False

    details = details_lookup('access', RESOURCE_CHANGE_EVENTS, event)
    return bool(details) and param_lookup(details.get('parameters', {}),
                                          'visibility') in PERMISSIVE_VISIBILITY


def dedup(event):
    return event['p_row_id']


def title(event):
    return 'User [{}] modified a document that has overly permissive share settings'.format(
        event.get('actor', {}).get('email'))
