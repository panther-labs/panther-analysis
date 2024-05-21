from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "APP":
        return False

    if event.get("type") == "CREATE":
        return True

    return False


def title(event):
    new_type = deep_get(event, "new", "type")
    return f"New app in use: {new_type}"
