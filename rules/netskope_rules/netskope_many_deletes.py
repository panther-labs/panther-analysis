def rule(event):
    audit_log_event = event.get("audit_log_event")
    if audit_log_event and "Delete" in audit_log_event:
        return True
    return False


def title(event):
    user = event.get("user", "<USER_NOT_FOUND>")
    return f"[{user}] deleted many objects in a short time"
