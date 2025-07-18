def rule(event):
    if event.deep_get("displaymessage", default="") == "User attempted unauthorized access to app":
        return True
    return False
