PREFIXES = ("Updated grant: ", "Created grant: ")


def rule(event):
    desc = event.get("description", "")
    return all(
        [
            event.get("requestUrl", "").startswith("/access/"),
            any(desc.startswith(prefix) for prefix in PREFIXES),
            "Admin" in desc,
        ]
    )


def title(event):
    user = event.get("loginName", "<NO_USERNAME_FOUND>")
    ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
    desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
    return f"{user} [{ip_addr}] {desc}"


def severity(event):
    if "Super Admin" in event.get("description", ""):
        return "CRITICAL"
    return "HIGH"
