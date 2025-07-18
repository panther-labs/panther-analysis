def rule(event):
    if event.deep_get("eventtype", default="") == "user.lifecycle.create":
        return True
    return False
