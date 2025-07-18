def rule(event):
    if event.deep_get("action", default="") in [
        "private_repository_forking.clear",
        "private_repository_forking.enable",
    ]:
        return True
    return False
