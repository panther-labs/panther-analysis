def rule(event):

    # check that this is a password change event;
    # event id 11 is actor_user changed password for user
    # Normally, admin's may change a user's password (event id 211)
    return event.get('event_type_id') == 11


def title(event):
    return 'A user [{}] password changed by user [{}]'.format(
        event.get('user_name'), event.get('actor_user_name'))
