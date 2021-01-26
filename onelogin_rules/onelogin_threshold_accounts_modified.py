def rule(event):
    # filter events; event type 11 is an actor_user changed user password
    return event.get('event_type_id') == 11


def title(event):
    return 'User [{}] has exceeded the user account password change threshold'.format(
        event.get('actor_user_name', '<UNKNOWN_USER>'))
