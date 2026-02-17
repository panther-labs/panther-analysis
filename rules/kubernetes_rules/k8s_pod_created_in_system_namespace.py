from panther_kubernetes_helpers import (
    SYSTEM_NAMESPACES,
    is_failed_request,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    subresource = event.udm("subresource")
    namespace = event.udm("namespace")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check pod creation events
    if verb != "create" or resource != "pods":
        return False

    # Only check direct pod creation, not subresources like eviction
    if subresource:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals (legitimate operators/controllers)
    if is_system_principal(username):
        return False

    # Alert if pod is created in a system namespace
    if namespace in SYSTEM_NAMESPACES:
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"

    return f"[{username}] created pod [{namespace}/{name}] in system namespace"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"
    return f"k8s_pod_system_ns_{username}_{namespace}_{name}"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    spec = request_object.get("spec", {})
    containers = spec.get("containers", [])

    # Extract container images
    images = [container.get("image") for container in containers if container.get("image")]

    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": event.udm("name"),
            "system_namespace": event.udm("namespace"),
            "container_images": images,
        },
    )
