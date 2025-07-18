def rule(event):
    if event.deep_get("eventtype", default="") == "system.api_token.revoke":
        return True
    return False
