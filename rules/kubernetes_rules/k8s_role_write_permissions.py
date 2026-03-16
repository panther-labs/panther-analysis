from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

# Write-related verbs that modify cluster state
WRITE_VERBS = {
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
}


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check Role/ClusterRole creation events
    if verb != "create" or resource not in {"roles", "clusterroles"}:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce noise from legitimate operators
    if is_system_principal(username):
        return False

    # Check if role grants write permissions
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])

    for rule_entry in rules:
        verbs = rule_entry.get("verbs", [])
        # Check if any write verb is present
        if any(verb in WRITE_VERBS for verb in verbs):
            return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    namespace = event.udm("namespace") or "<CLUSTER_SCOPED>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"

    if namespace != "<CLUSTER_SCOPED>":
        return f"[{username}] created {role_type} [{namespace}/{name}] with write " f"permissions"

    return f"[{username}] created {role_type} [{name}] with write permissions " f""


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    return f"k8s_role_write_{username}_{resource}_{name}"


def severity(event):
    """Increase severity for dangerous combinations of write permissions."""
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])
    resource = event.udm("resource") or ""

    # Check for high-risk resource + write verb combinations
    for rule_entry in rules:
        resources_list = rule_entry.get("resources", [])
        verbs = rule_entry.get("verbs", [])

        # Critical: Write access to secrets or RBAC resources
        sensitive_resources = {
            "secrets",
            "clusterroles",
            "clusterrolebindings",
            "roles",
            "rolebindings",
        }
        if any(res in sensitive_resources for res in resources_list) and any(
            v in {"create", "update", "patch", "delete"} for v in verbs
        ):
            return "CRITICAL"

        # High: ClusterRole with write to pods or nodes
        if resource == "clusterroles" and any(
            res in {"pods", "nodes", "persistentvolumes"} for res in resources_list
        ):
            if any(v in {"create", "update", "patch", "delete"} for v in verbs):
                return "HIGH"

    # Medium: ClusterRole with general write permissions
    if resource == "clusterroles":
        return "MEDIUM"

    # Low: Namespaced Role with write permissions (common/expected)
    return "LOW"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])

    # Extract only the rules that contain write verbs
    write_rules = []
    for rule_entry in rules:
        verbs = rule_entry.get("verbs", [])
        if any(verb in WRITE_VERBS for verb in verbs):
            write_rules.append(rule_entry)

    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": event.udm("name"),
            "role_type": event.udm("resource"),
            "write_rules": write_rules,
        },
    )
