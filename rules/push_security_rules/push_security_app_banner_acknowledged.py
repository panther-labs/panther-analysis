def rule(event):
    if event.get("object") != "APP_BANNER":
        return False

    if event.deep_get("new", "action") == "ACKNOWLEDGED":
        return True

    return False


def title(event):
    app_type = event.deep_get("new", "appType")
    employee_email = event.deep_get("new", "employee", "email")
    return f"{app_type} accessed by {employee_email}"


def alert_context(event):
    return {
        "Push Security app banner": event.deep_get("new", "appBanner", "mode"),
        "Title": event.deep_get("new", "appBanner", "title"),
        "Subtext": event.deep_get("new", "appBanner", "subtext"),
        "Button": event.deep_get("new", "appBanner", "buttonText"),
    }
