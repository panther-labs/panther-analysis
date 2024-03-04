def rule(event):
    if event.get("audit_log_event") == "Admin logged out because of successive login failures":
        return True
    return False


def title(event):
    user = event.get("user", "<USER_NOT_FOUND>")
    return f"Admin [{user}] was logged out because of successive login failures"
