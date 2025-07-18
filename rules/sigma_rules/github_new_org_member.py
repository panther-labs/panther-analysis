def rule(event):
    if event.deep_get("action", default="") in ["org.add_member", "org.invite_member"]:
        return True
    return False
