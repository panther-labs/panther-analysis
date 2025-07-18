def rule(event):
    if event.deep_get("eventtype", default="") == "system.api_token.create":
        return True
    return False
