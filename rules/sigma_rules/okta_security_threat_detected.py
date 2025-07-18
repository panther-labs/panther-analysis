def rule(event):
    if event.deep_get("eventtype", default="") == "security.threat.detected":
        return True
    return False
