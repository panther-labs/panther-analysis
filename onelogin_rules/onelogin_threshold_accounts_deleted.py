def rule(event):

    # filter events; event type 17 is a user deleted
    return event.get('event_type_id') == 17


def dedup(event):
    # the deleted user's user_name
    return event.get('user_name')


def title(event):
    return 'User [{}] has exceeded the user account deletion threshold'.format(
        event.get('actor_user_name'))
