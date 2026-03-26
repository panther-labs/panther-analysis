def rule(event):
    if event.get("object") == "PASSWORD_PHISHING":
        return True

    return False


def severity(event):
    if event.deep_get("new", "mode") != "BLOCK":
        return "HIGH"
    return "LOW"


def title(event):
    app_type = event.deep_get("new", "appType")
    employee_email = event.deep_get("new", "employee", "email")
    new_mode = event.deep_get("new", "mode")
    return f"Phishing attack on app {app_type} user {employee_email}. \
             Attack detected in mode {new_mode}."
