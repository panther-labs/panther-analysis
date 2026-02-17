from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

# System roles that are expected to change during normal operations
# Users can extend this list for their environment
ALLOWED_SYSTEM_ROLE_MODIFICATIONS = {
    "system:coredns",
    "system:managed-certificate-controller",
}


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    username = event.udm("username")
    response_status = event.udm("responseStatus")
    name = event.udm("name") or ""

    # Only check role/clusterrole modification/deletion events
    if verb not in {"update", "patch", "delete"} or resource not in {
        "roles",
        "clusterroles",
    }:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce false positives
    if is_system_principal(username):
        return False

    # Check if role name starts with "system:" or "eks:" (EKS system roles)
    if not (name.startswith("system:") or name.startswith("eks:")):
        return False

    # Exclude roles that are expected to change
    if name in ALLOWED_SYSTEM_ROLE_MODIFICATIONS:
        return False

    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    verb = event.udm("verb") or "<UNKNOWN_VERB>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    namespace = event.udm("namespace") or "<CLUSTER_SCOPED>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"
    action = "deleted" if verb == "delete" else "modified"

    if namespace != "<CLUSTER_SCOPED>":
        return f"[{username}] {action} system {role_type} [{namespace}/{name}]"

    return f"[{username}] {action} system {role_type} [{name}]"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    return f"k8s_system_role_{username}_{name}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": event.udm("name"),
            "role_type": event.udm("resource"),
            "modification_type": event.udm("verb"),
        },
    )
