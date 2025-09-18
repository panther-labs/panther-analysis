def rule(event):
    action = event.deep_get("event", "action", default="")
    if action == "AuditAction.ResetApiKey":
        return True
    return False


def title(event):
    username = event.deep_get("event", "user", default="")
    return f"[Axonius] API Key Reset for {username} Detected"
