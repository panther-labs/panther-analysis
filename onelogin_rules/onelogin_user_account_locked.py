def rule(event):

    # check for a user locked event
    # event 531 and 553 are user lock events via api
    # event 551 is user suspended via api
    return event.get("event_type_id") in [531, 553, 551]


def title(event):
    return "A user [{}] was locked or suspended via api call".format(
        event.get("user_name", "<UNKNOWN_USER>")
    )
