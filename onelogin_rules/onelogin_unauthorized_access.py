def rule(event):
    # filter events; event type 90 is an unauthorized application access event id
    return event.get('event_type_id') == 90


def title(event):
    return 'User [{}] has exceeded the unauthorized application access attempt threshold'.format(
        event.get('user_name', '<UNKNOWN_USER>'))
