def rule(event):
    return event.get("action", "") == "create" and event.get("source_type") == "api_token"


def title(event):
    return f"[{event.get('p_log_type')}]: User [{event.udm('actor_user')}] created a new api token"
