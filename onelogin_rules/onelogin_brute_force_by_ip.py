def rule(event):
    # filter events; event type 6 is a failed authentication
    return event.get('event_type_id') == 6


def dedup(event):
    return event.get('ipaddr', '<UNKNOWN_IP>')


def title(event):
    return 'IP [{}] has exceeded the failed logins threshold'.format(
        event.get('ipaddr'))
