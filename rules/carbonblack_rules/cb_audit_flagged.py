def rule(event):
    return event.get("flagged", False)


def title(event):
    user = event.get("loginName", "<NO_USERNAME_FOUND>")
    ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
    desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
    return f"{user} [{ip_addr}] {desc}"
