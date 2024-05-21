def rule(event):
    if event.get("object") != "FINDING":
        return False

    event_type = event.get("type")

    if event_type == "CREATE":
        return True

    if event_type == "UPDATE" and event.deep_get("new", "state") == "OPEN":
        return True

    return False


def title(event):
    new_type = event.deep_get("new", "type")
    app_type = event.deep_get("new", "appType")
    return f"Open finding {new_type} for app {app_type}"
