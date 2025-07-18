def rule(event):
    if event.deep_get("displaymessage", default="") == "Max sign in attempts exceeded":
        return True
    return False
