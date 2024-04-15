from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") != "ACCOUNT":
        return False

    if event.get("type") == "CREATE":
        return True

    return False


def title(event):
    return f"New account on {deep_get(event, 'new', 'appType')} created by {deep_get(event, 'new', 'email')}"
