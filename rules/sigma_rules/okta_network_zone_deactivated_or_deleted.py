def rule(event):
    if event.deep_get("eventtype", default="") in ["zone.deactivate", "zone.delete"]:
        return True
    return False
