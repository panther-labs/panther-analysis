def rule(event):
    action = event.deep_get("event", "action", default="")
    category = event.deep_get("event", "category", default="")
    if action == "AuditAction.Put" and category == "AuditCategory.WebhookManagement":
        return True
    return False


def title(event):
    username = event.deep_get("event", "user", default="")
    return f"[Axonius] API Key Reset for {username} Detected"


def alert_context(event):
    username = event.deep_get("event", "user", default="")
    config_id = event.deep_get("event", "params", "config_id", default="")
    vendor_name = event.deep_get("event", "params", "vendor_name", default="")
    event_type = event.deep_get("event", "type", default="")

    context = {
        "username": username,
        "config_id": config_id,
        "vendor_name": vendor_name,
        "type": event_type,
    }
    return context
