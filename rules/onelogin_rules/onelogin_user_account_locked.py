def rule(event):

    # check for a user locked event
    # event 531 and 553 are user lock events via api
    # event 551 is user suspended via api
    return str(event.get("event_type_id")) in ["531", "553", "551"]


def title(event):
    return (
        f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] was locked or suspended via api call"
    )
