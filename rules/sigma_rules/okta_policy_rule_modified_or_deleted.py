def rule(event):
    if event.deep_get("eventtype", default="") in ["policy.rule.update", "policy.rule.delete"]:
        return True
    return False
