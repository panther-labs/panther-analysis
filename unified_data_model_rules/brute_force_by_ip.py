import panther_event_type_helpers as event_type

def rule(event):
    # filter events on unified data model field
    return bool(event.udm('event_type')) and event.udm('event_type') == event_type.FAILED_LOGIN


def title(event):
    # use unified data model field in title
    return '{}: User [{}] from IP [{}] has exceeded the failed logins threshold'.format(
        event.get('p_log_type'), event.udm('actor_user'), event.udm('source_ip'))
