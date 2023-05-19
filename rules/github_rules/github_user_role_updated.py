from global_filter_github import filter_include_event


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "org.update_member"


def title(event):
    return (
        f"Org owner [{event.udm('actor_user')}] updated user's "
        f"[{event.get('user')}] role ('admin' or 'member')"
    )
