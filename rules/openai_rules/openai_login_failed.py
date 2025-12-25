def rule(event):
    return event.get("type") == "login.failed"
