def rule(event):

    # check that this is a password change event;
    # event id 11 is actor_user changed password for user
    # Normally, admin's may change a user's password (event id 211)
    if event.get('event_type_id') != 11 or not event.get(
            'actor_user_id') or not event.get('user_id'):
        return False

    # user changed another user's password
    return event.get('actor_user_id') != event.get('user_id')


def dedup(event):
    return event.get('user_id')


def title(event):
    return 'A user [{}] password changed by another user [{}]'.format(
        event.get('user_name'), event.get('actor_user_name'))
