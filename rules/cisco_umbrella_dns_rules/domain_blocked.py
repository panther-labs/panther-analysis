def rule(event):
    return event.get("action") == "Blocked"


def title(event):
    return f"Access denied to domain {event.get('domain', '<UNKNOWN_DOMAIN>')}"
