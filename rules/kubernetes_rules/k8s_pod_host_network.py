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

    # Check if hostNetwork is set to true in the request
    host_network = event.udm("hostNetwork")
    if host_network is True:
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"

    return f"[{username}] created pod [{namespace}/{name}] with host network access "


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": event.udm("name"),
            "hostNetwork": event.udm("hostNetwork"),
        },
    )
