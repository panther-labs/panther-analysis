def rule(event):

    # Filter events; event type 240 is actor_user revealed user's app password
    if (
        event.get("event_type_id") != 240
        or not event.get("actor_user_id")
        or not event.get("user_id")
    ):
        return False

    # Determine if actor_user accessed another user's password
    return event.get("actor_user_id") != event.get("user_id")


def dedup(event):
    return event.get("actor_user_name") + ":" + event.get("app_name", "<UNKNOWN_APP>")


def title(event):
    return (
        f"A user [{event.get('actor_user_name', '<UNKNOWN_USER>')}] accessed another user's "
        f"[{event.get('user_name', '<UNKNOWN_USER>')}] "
        f"[{event.get('app_name', '<UNKNOWN_APP>')}] password"
    )
