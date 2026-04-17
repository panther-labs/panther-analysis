def rule(event):
    if event.get("is_netskope_personnel") is True:
        return True
    return False


def title(event):
    user = event.get("user", "<USER_NOT_FOUND>")
    audit_log_event = event.get("audit_log_event", "<EVENT_NOT_FOUND>")
    return f"Action [{audit_log_event}] performed by Netskope personnel [{user}]"
