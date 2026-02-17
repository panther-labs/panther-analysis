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

    # Only check pod creation events
    if verb != "create" or resource != "pods":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals creating pods in system namespaces (legitimate)
    # but alert on system principals in user namespaces (malicious Deployments)
    # and alert on user-created pods in system namespaces (suspicious)
    if is_system_principal(username) and is_system_namespace(namespace):
        return False

    # Check if hostIPC is enabled
    host_ipc = event.udm("hostIPC")
    if host_ipc is True:
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"

    return f"[{username}] created pod [{namespace}/{name}] with host IPC enabled "


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_host_ipc_{username}_{namespace}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": event.udm("name"),
            "hostIPC": event.udm("hostIPC"),
        },
    )
