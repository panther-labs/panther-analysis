from global_filter_github import filter_include_event


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "public_key.create"


def title(event):
    return f"User [{event.udm('actor_user')}] created a new ssh key"
