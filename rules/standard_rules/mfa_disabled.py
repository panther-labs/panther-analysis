import panther_event_type_helpers as event_type


def rule(event):
    return event.udm("event_type") == event_type.MFA_DISABLED


def generate_alert_title(event):
    # use unified data model field in title
    return f"ALERT: {event.get('p_log_type')} - User [{event.udm('actor_user')}] has disabled MFA"
