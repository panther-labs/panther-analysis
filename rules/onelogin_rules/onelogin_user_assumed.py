def rule(event):
    # check that this is a user assumption event; event id 3
    return str(event.get("event_type_id")) == "3" and event.get(
        "actor_user_id", "UNKNOWN_USER"
    ) != event.get("user_id", "UNKNOWN_USER")


def title(event):
    return (
        f"A user [{event.get('actor_user_name', '<UNKNOWN_USER>')}] assumed another user "
        f"[{event.get('user_name', '<UNKNOWN_USER>')}] account"
    )
