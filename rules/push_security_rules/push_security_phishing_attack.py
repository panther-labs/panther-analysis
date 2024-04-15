from panther_base_helpers import deep_get


def rule(event):
    if event.get("object") == "PASSWORD_PHISHING":
        return True

    return False


def severity(event):
    if deep_get(event, "new", "mode") != "BLOCK":
        return "HIGH"
    return "LOW"


def title(event):
    return f"Phishing attack on app {deep_get(event, 'new', 'appType')} user {deep_get(event, 'new', 'employee', 'email')}. Attack detected in mode {deep_get(event, 'new', 'mode')}."
