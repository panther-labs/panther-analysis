def rule(event):
    if event.deep_get("eventtype", default="") == "iam.resourceset.bindings.add":
        return True
    return False
