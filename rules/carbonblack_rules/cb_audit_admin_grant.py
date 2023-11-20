PREFIXES = ("Updated grant: ", "Created grant: ")


def rule(event):
    if not event.get("requestUrl", "").startswith("/access/"):
        return False
    desc = event.get("description", "")
    if not any([desc.startswith(prefix) for prefix in PREFIXES]):
        return False
    if "Admin" in desc:
        return True
    return False


def title(event):
    user = event.get("loginName", "<NO_USERNAME_FOUND>")
    ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
    desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
    return f"{user} [{ip_addr}] {desc}"


def severity(event):
    if "Super Admin" in event.get("description", ""):
        return "CRITICAL"
    return "HIGH"
