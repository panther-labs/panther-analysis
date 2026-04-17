from panther_kubernetes_helpers import k8s_alert_context


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    subresource = event.udm("subresource")

    # Check for exec action on pods
    if verb in ("create", "get") and resource == "pods" and subresource == "exec":
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    pod_name = event.udm("name") or "<UNKNOWN>"

    return f"[{username}] executed into pod [{namespace}/{pod_name}]"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    pod_name = event.udm("name") or "<UNKNOWN_POD>"
    return f"k8s_exec_{username}_{namespace}_{pod_name}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={"pod_name": event.udm("name")},
    )
