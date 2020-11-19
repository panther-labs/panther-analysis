import panther_event_type_helpers as event_type

def rule(event):
    # filter events on unified data model field
    if event.udm('event_type'):
        return event.udm('event_type') == event_type.ADMIN_ROLE_ASSIGNED
    return False


def title(event):
    # use unified data model field in title
    return '{}: [{}] assigned admin privileges [{}] to [{}]'.format(
        event.get('p_log_type'), event.udm('actor_user'), event.udm('admin_role'), event.udm('user'))
