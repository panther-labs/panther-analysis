def rule(event):
    if event.deep_get("eventtype", default="") in [
        "application.policy.sign_on.update",
        "application.policy.sign_on.rule.delete",
    ]:
        return True
    return False
