def rule(event):

    # check risk associated with this event
    if event.get('risk_score', 0) > 50:
        # a failed authentication attempt with high risk
        return event.get('event_type_id') == 6
    return False


def title(event):
    return 'A user [{}] failed a high risk login attempt'.format(
        event.get('user_name', '<UNKNOWN_USER>'))
