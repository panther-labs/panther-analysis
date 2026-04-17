def rule(event):
    return event.get("eventName") == "ConsoleLogin"


def alert_context(event):
    context = {}
    context["ip_and_username"] = event.get(
        "sourceIPAddress", "<MISSING_SOURCE_IP>"
    ) + event.deep_get("userIdentity", "userName", default="<MISSING_USER_NAME>")
    return context
