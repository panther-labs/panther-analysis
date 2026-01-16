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
    user = event.get("user", "<UNKNOWN_USER>")
    new_ip = event.get("new_ip", "<UNKNOWN_IP>")
    request_count = event.get("request_count", 0)
    return (
        f"Google Workspace: User [{user}] made {request_count} OAuth token requests "
        f"from new IP [{new_ip}]"
    )


def alert_context(event):
    user = event.get("user")
    return {
        "user": user,
        "username_normalized": normalize_username(user),
        "new_ip": event.get("new_ip"),
        "request_count": event.get("request_count"),
        "app_names": event.get("app_names"),
        "client_ids": event.get("client_ids"),
        "first_seen": event.get("first_seen"),
        "last_seen": event.get("last_seen"),
        "description": (
            "User requested OAuth tokens from an IP address not seen in the past 30 days, "
            "with multiple requests indicating active usage"
        ),
    }
