from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "APP_BANNER":
        return False

    if deep_get(event, "new", "action") == "ACKNOWLEDGED":
        return True

    return False


def title(event):
    return f"{deep_get(event, 'new', 'appType')} accessed by {deep_get(event, 'new', 'employee', 'email')}"


def alert_context(event):
    return {
        "Push Security app banner": deep_get(event, "new", "appBanner", "mode"),
        "Title": deep_get(event, "new", "appBanner", "title"),
        "Subtext": deep_get(event, "new", "appBanner", "subtext"),
        "Button": deep_get(event, "new", "appBanner", "buttonText"),
    }
