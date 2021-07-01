def rule(event):
    return event.get("action") == "public_key.create"


def title(event):
    return f"User [{event.udm('actor_user')}] created a new ssh key"
