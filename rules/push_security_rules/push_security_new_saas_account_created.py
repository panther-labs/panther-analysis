from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    if event.get("type") == "CREATE":
        return True

    return False


def title(event):
    app_type = deep_get(event, "new", "appType")
    new_email = deep_get(event, "new", "email")
    return f"New account on {app_type} created by {new_email}"
