def rule(event):
    if event.deep_get("eventtype", default="") in [
        "policy.lifecycle.update",
        "policy.lifecycle.delete",
    ]:
        return True
    return False
