import re


def normalize_username(email):
    if not email:
        return None
    # Extract username before @ symbol
    username = email.split("@")[0] if "@" in email else email
    # Remove all non-alphanumeric characters and convert to lowercase
    return re.sub(r"[^a-z0-9]", "", username.lower())


def rule(_):
    return True


def title(event):
    user = event.get("email", "<UNKNOWN_USER>")
    login_type = event.get("login_type", "<UNKNOWN_TYPE>")
    return f"Google Workspace: User [{user}] used anomalous login type [{login_type}]"


def severity(event):
    login_type = event.get("login_type", "")

    # Higher severity for password-based auth
    if login_type == "google_password":
        return "HIGH"

    return "MEDIUM"


def alert_context(event):
    email = event.get("email")
    return {
        "user_email": email,
        "username_normalized": normalize_username(email),
        "anomalous_login_type": event.get("login_type"),
        "ip_address": event.get("ipAddress"),
        "description": ("User authenticated with a login type not seen in the previous 30 days"),
    }
