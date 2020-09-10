def rule(event):

    # check that this is a user assumption event; event id 3
    return event.get('event_type_id') == 3 and event.get(
        'actor_user_id', 'UNKNOWN_USER') != event.get('user_id', 'UNKNOWN_USER')


def title(event):
    return 'A user [{}] assumed another user [{}] account'.format(
        event.get('actor_user_name'), event.get('user_name'))
