def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    if event.get("type") == "CREATE":
        return True

    return False


def title(event):
    app_type = event.deep_get("new", "appType")
    new_email = event.deep_get("new", "email")
    return f"New account on {app_type} created by {new_email}"
