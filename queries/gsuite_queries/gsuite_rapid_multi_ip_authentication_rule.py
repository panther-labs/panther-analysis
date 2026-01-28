def rule(_):
    return True


def title(event):
    user = event.get("user", "<UNKNOWN_USER>")
    ip_count = event.get("unique_ip_count", 0)
    return f"Google Workspace: User [{user}] authenticated from {ip_count} distinct IPs in 6 hours"


def severity(event):
    ip_count = event.get("unique_ip_count", 0)

    # Very high IP count suggests active credential spread
    if ip_count >= 4:
        return "HIGH"

    return "MEDIUM"


def alert_context(event):
    return {
        "user": event.get("user"),
        "unique_ip_count": event.get("unique_ip_count"),
        "ip_addresses": event.get("ip_addresses"),
        "login_types": event.get("login_types"),
        "first_login": event.get("first_login"),
        "last_login": event.get("last_login"),
        "time_span_minutes": event.get("time_span_minutes"),
        "total_logins": event.get("total_logins"),
        "description": (
            "User authenticated from multiple distinct IPv4 addresses in a short time window"
        ),
    }
