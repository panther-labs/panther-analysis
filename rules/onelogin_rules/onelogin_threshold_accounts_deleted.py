def rule(event):

    # filter events; event type 17 is a user deleted
    return str(event.get("event_type_id")) == "17"


def title(event):
    return (
        f"User [{event.get('actor_user_name', '<UNKNOWN_USER>')}] "
        f"has exceeded the user account deletion threshold"
    )
