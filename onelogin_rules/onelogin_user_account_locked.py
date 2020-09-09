def rule(event):

    # check for a user locked event
    # event 531 and 553 are user lock events via api
    return event.get('event_type_id') in [531, 553]


def dedup(event):
    return event.get('user_name')


def title(event):
    return 'A user [{}] was locked by the api'.format(event.get('user_name'))
