def rule(event):
    # filter events; event type 11 is an actor_user changed user password
    return event.get("event_type_id") == 11


def title(event):
    return (
        f"User [{event.get('actor_user_name', '<UNKNOWN_USER>')}] has exceeded the user"
        f" account password change threshold"
    )
