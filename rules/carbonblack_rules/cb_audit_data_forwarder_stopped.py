ACTION = ""


def rule(event):
    # pylint: disable=global-statement
    global ACTION
    if not event.get("requestUrl", "").startswith("/data_forwarder/"):
        return False
    desc = event.get("description", "")
    if desc.startswith("Deleted Config: "):
        ACTION = "Deleted"
        return True
    if desc.startswith("Updated Config: ") and '"enabled":false' in desc:
        ACTION = "Disabled"
        return True
    return False


def title(event):
    user = event.get("loginName", "<NO_USERNAME_FOUND>")
    ip_addr = event.get("clientIp", "<NO_IP_FOUND>")
    return f"{user} [{ip_addr}] {ACTION} Data Forwarder"


def description(event):
    user = event.get("loginName")
    ip_addr = event.get("clientIp")
    desc = event.get("description")
    return f"{user} [{ip_addr}] {desc}"
