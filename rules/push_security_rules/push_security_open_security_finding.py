from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "FINDING":
        return False

    event_type = event.get("type")

    if event_type == "CREATE":
        return True

    if event_type == "UPDATE" and deep_get(event, "new", "state") == "OPEN":
        return True

    return False


def title(event):
    return (
        f"Open finding {deep_get(event, 'new', 'type')} for app {deep_get(event, 'new', 'appType')}"
    )
