def rule(event):
    # filter events; event type 90 is an unauthorized applicaiton access event id
    return event.get('event_type_id') == 90


def dedup(event):
    return event.get('user_id')


def title(event):
    return 'User [{}] has exceeded the unauthorized application access attempt threshold'.format(
        event.get('user_name', '<UNKNOWN_USER>'))
