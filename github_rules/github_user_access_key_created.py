def rule(event):
    return event.get("action") == "public_key.create"

def title(event):
    return (
      f"User [{event.get('actor_user', '<UNKNOWN_ACTOR_USER>')}] created a new ssh key"
    )
