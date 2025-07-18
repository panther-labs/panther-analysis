def rule(event):
    if event.deep_get("eventtype", default="") == "system.idp.lifecycle.create":
        return True
    return False
