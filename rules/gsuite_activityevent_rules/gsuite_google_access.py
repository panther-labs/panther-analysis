def rule(event):
    if event.deep_get("id", "applicationName") != "access_transparency":
        return False

    return bool(event.get("type") == "GSUITE_RESOURCE")
