PATTERNS = ("Added user ",)


def rule(event):
    desc = event.get("description", "")
    if not any(desc.startswith(pattern) for pattern in PATTERNS):
        return False
    src_user = event.get("loginName", "")
    src_domain = src_user.split("@")[1]
    dst_user = desc.split(" ")[2]
    dst_domain = dst_user.split("@")[1]
    if src_domain != dst_domain:
        return True
    return False


def title(event):
    user = event.get("loginName", "<NO_USERNAME_FOUND>")
    ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
    desc = event.get("description", "<NO_DESCRIPTION_FOUND>")
    return f"{user} [{ip_addr}] {desc}"
