def rule(event):
    return event.get("action") == "org.update_member"


def title(event):
    return f"User [{event.udm('actor_user')}] updated user's [{event.get('user')}] role ('admin' or 'member')"
