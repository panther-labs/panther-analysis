from panther_kubernetes_helpers import is_failed_request, k8s_alert_context


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    response_status = event.udm("responseStatus")

    # Only check service creation events
    if verb != "create" or resource != "services":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Check if service type is NodePort
    service_type = event.udm("serviceType") or ""
    if service_type == "NodePort":
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN>"

    return f"[{username}] deployed NodePort service [{namespace}/{name}]"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "service_name": event.udm("name"),
            "service_type": event.udm("serviceType"),
        },
    )
