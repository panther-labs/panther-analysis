from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

SECRET_VERBS = {"list", "get", "watch"}


def rule(event):
    if event.udm("verb") not in SECRET_VERBS:
        return False
    if event.udm("resource") != "secrets":
        return False
    if is_system_principal(event.udm("username") or ""):
        return False
    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    return f"Kubernetes Secret Enumeration by [{username}]"


def dedup(event):
    username = event.udm("username") or ""
    user_agent = event.udm("userAgent") or ""
    return f"{username}:{user_agent}"


def unique(event):
    return event.udm("name") or None


def severity(event):
    if not is_failed_request(event.udm("responseStatus")):
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "secret_name": event.udm("name"),
            "verb": event.udm("verb"),
            "user_agent": event.udm("userAgent"),
        },
    )
