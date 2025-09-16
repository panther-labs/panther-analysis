def rule(event):
    action = event.deep_get("event", "action", default="")
    category = event.deep_get("event", "category", default="")
    if action == "AuditAction.AddExternalUser" and category == "AuditCategory.UserManagement":
        return True
    return False


def title(event):
    username = event.deep_get("event", "params", "user_name", default="")
    source = event.deep_get("event", "params", "source", default="")
    return f"[Axonius] External User {username} added from {source}"


def alert_context(event):
    username = event.deep_get("event", "params", "user_name", default="")
    source = event.deep_get("event", "params", "source", default="")
    context = {
        "username": username,
        "source": source,
    }
    return context
