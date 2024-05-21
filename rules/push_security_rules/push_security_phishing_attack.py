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
    app_type = deep_get(event, "new", "appType")
    employee_email = deep_get(event, "new", "employee", "email")
    new_mode = deep_get(event, "new", "mode")
    return f"Phishing attack on app {app_type} user {employee_email}. \
             Attack detected in mode {new_mode}."
