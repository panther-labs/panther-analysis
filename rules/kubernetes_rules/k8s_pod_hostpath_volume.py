from panther_kubernetes_helpers import (
    get_hostpath_paths,
    has_hostpath_volume,
    is_failed_request,
    is_sensitive_hostpath,
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

    # Check for hostPath volumes
    volumes = event.udm("volumes") or []
    if has_hostpath_volume(volumes):
        return True

    return False


def severity(event):
    volumes = event.udm("volumes") or []
    paths = get_hostpath_paths(volumes)

    for path in paths:
        if is_sensitive_hostpath(path):
            return "HIGH"

    return "DEFAULT"


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"

    volumes = event.udm("volumes") or []
    paths = get_hostpath_paths(volumes)
    paths_str = ", ".join(paths) if paths else "unknown"

    return (
        f"[{username}] created pod [{namespace}/{name}] with hostPath volume mount "
        f"[{paths_str}]"
    )


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    return f"hostpath_volume_{username}_{namespace}"


def alert_context(event):
    volumes = event.udm("volumes") or []

    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": event.udm("name"),
            "volumes": volumes,
            "hostpath_paths": get_hostpath_paths(volumes),
        },
    )
