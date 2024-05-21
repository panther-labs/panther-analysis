def rule(event):
    if event.get("object") != "APP":
        return False

    if event.get("type") == "CREATE":
        return True

    return False


def title(event):
    new_type = event.deep_get("new", "type")
    return f"New app in use: {new_type}"
