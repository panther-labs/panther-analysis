def rule(event):
    if event.deep_get("eventtype", default="") in [
        "user.mfa.factor.deactivate",
        "user.mfa.factor.reset_all",
    ]:
        return True
    return False
