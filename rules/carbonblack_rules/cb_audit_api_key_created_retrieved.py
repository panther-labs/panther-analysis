PATTERNS = (
    " retrieved secret for API ID ",
    "Added API ID ",
    "Regenerated API key for API ID ",
    "Updated API ID ",
)


def rule(event):
    desc = event.get("description", "")
    for pattern in PATTERNS:
        if pattern in desc:
            return True
    return False


def title(event):
    user = event.get("loginName", "<NO_USERNAME_FOUND>")
    ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
    desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
    return f"{user} [{ip_addr}] {desc}"
