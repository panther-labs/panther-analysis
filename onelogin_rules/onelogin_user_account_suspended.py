def rule(event):

    # check that this is a user suspended event
    # event 21 is user suspended event; event 551 is user suspended via api
    return event.get('event_type_id') in [21, 551]


def title(event):
    return 'A user [{}] was suspended by [{}]'.format(
        event.get('user_name'), event.get('actor_user_name'))
