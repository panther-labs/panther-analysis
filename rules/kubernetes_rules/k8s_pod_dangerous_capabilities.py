from panther_base_helpers import deep_get
from panther_kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)

# Dangerous Linux capabilities that enable privilege escalation or container escape
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",  # Most powerful
    "NET_ADMIN",  # Network manipulation
    "BPF",  # eBPF programs
    "SYS_PTRACE",  # Process tracing
    "SYS_MODULE",  # Load kernel modules
    "DAC_READ_SEARCH",  # Bypass file read permission checks
    "DAC_OVERRIDE",  # Bypass file permission checks
}


def has_dangerous_capabilities(containers):
    """Check if any container has dangerous Linux capabilities."""
    if not containers:
        return []

    dangerous_caps_found = []

    for container in containers:
        added_caps = deep_get(container, "securityContext", "capabilities", "add", default=[])

        if added_caps:
            # Check for intersection with dangerous capabilities
            dangerous = set(added_caps) & DANGEROUS_CAPABILITIES
            if dangerous:
                dangerous_caps_found.extend(list(dangerous))

    return dangerous_caps_found


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

    # Exclude system namespaces and system principals to reduce false positives
    if is_system_namespace(namespace) or is_system_principal(username):
        return False

    # Check for dangerous capabilities
    containers = event.udm("containers") or []
    dangerous_caps = has_dangerous_capabilities(containers)

    if dangerous_caps:
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"

    containers = event.udm("containers") or []
    dangerous_caps = has_dangerous_capabilities(containers)
    caps_str = ", ".join(sorted(set(dangerous_caps)))

    return (
        f"[{username}] created pod [{namespace}/{name}] with dangerous capabilities "
        f"[{caps_str}]"
    )


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_dangerous_caps_{username}_{namespace}"


def alert_context(event):
    containers = event.udm("containers") or []
    dangerous_caps = has_dangerous_capabilities(containers)

    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": event.udm("name"),
            "containers": containers,
            "dangerous_capabilities": sorted(set(dangerous_caps)),
        },
    )
