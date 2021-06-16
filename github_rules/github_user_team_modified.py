def rule(event):
    return (
        event.get("action") == "team.create" or
        event.get("action") == "team.delete" or
        event.get("action") == "user.create" or
        event.get("action") == "user.delete"
    )

def title(event):
    # TODO: determine if user or repo added/removed
    action = "added"
    if event.get("action").endswith(".delete"):
        action = "removed"
    if event.get("action").startswith("team"):
        return (
            # TODO: add team info
            f"User [{event.get('actor_user', '<UNKNOWN_ACTOR_USER>')}] {action} from team [{event.get('team')}]"
        )
    return (
        f"User [{event.get('actor_user', '<UNKNOWN_ACTOR_USER>')}] {action}"
    )
