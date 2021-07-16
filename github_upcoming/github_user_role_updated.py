def rule(event):
    return event.get("action") == "org.update_member"


def title(event):
    return (
        f"Org owner [{event.udm('actor_user')}] updated user's "
        f"[{event.get('user')}] role ('admin' or 'member')"
    )
