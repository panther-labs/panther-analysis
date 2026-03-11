from panther_kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    namespace = event.udm("namespace")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check secret get operations
    if verb != "get" or resource != "secrets":
        return False

    # Only alert on failed requests (access denied)
    if not is_failed_request(response_status):
        return False

    # Exclude system namespaces and system principals
    if is_system_namespace(namespace) or is_system_principal(username):
        return False

    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_SECRET>"
    response_status = event.udm("responseStatus") or {}
    status_code = response_status.get("code", "UNKNOWN")

    return (
        f"[{username}] failed secret enumeration attempt "
        f"in [{namespace}/{name}] "
        f"(response: {status_code})"
    )


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_secret_denied_{username}_{namespace}"


def alert_context(event):
    response_status = event.udm("responseStatus") or {}

    return k8s_alert_context(
        event,
        extra_fields={
            "secret_name": event.udm("name"),
            "response_code": response_status.get("code"),
            "response_message": response_status.get("message"),
        },
    )
