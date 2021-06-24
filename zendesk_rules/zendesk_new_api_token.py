def rule(event):
    return event.get("source_type") == "api_token" and event.get("action", "") in {"create","destroy"}


def title(event):
    action = event.get("action", "<UNKNOWN_ACTION>")
    return f"[{event.get('p_log_type')}]: User [{event.udm('actor_user')}] {action} an api token"


def severity(event):
    if event.get("action","") == "destroy":
        return "INFO"
    return "HIGH"
