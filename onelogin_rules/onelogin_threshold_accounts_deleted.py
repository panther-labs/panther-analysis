def rule(event):

    # filter events; event type 17 is a user deleted
    return event.get('event_type_id') == 17


def title(event):
    return 'User [{}] has exceeded the user account deletion threshold'.format(
        event.get('actor_user_name', '<UNKNOWN_USER>'))
