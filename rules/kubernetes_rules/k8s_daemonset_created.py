from panther_kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    response_status = event.udm("responseStatus")
    namespace = event.udm("namespace")
    username = event.udm("username")

    # Check for DaemonSet create operation
    if verb == "create" and resource == "daemonsets":
        # Only alert on successful operations
        if is_failed_request(response_status):
            return False

        # Exclude system controllers creating DaemonSets in system namespaces
        if is_system_namespace(namespace) and is_system_principal(username):
            return False

        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    daemonset_name = event.udm("name") or "<UNKNOWN>"

    return f"[{username}] created DaemonSet [{namespace}/{daemonset_name}]"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_daemonset_{username}_{namespace}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "daemonset_name": event.udm("name"),
            "requestObject": event.udm("requestObject"),
        },
    )
