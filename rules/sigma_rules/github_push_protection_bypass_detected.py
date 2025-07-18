def rule(event):
    if "secret_scanning_push_protection.bypass" in event.deep_get("action", default=""):
        return True
    return False
