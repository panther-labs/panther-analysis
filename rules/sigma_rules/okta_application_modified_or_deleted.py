def rule(event):
    if event.deep_get("eventtype", default="") in [
        "application.lifecycle.update",
        "application.lifecycle.delete",
    ]:
        return True
    return False
