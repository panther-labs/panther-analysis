from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context


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

    # Exclude system principals to reduce false positives from legitimate operators
    if is_system_principal(username):
        return False

    # Check if role grants pods/exec permissions
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])

    for rule_entry in rules:
        resources = rule_entry.get("resources", [])
        # Check for pods/exec subresource
        if "pods/exec" in resources:
            return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    namespace = event.udm("namespace") or "<CLUSTER_SCOPED>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"

    if namespace != "<CLUSTER_SCOPED>":
        return f"[{username}] created {role_type} [{namespace}/{name}] with pods/exec permissions"

    return f"[{username}] created {role_type} [{name}] with pods/exec permissions "


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    return f"k8s_role_podexec_{username}_{resource}_{name}"


def severity(event):
    """ClusterRoles are more dangerous than namespaced Roles."""
    resource = event.udm("resource") or ""

    # Critical for ClusterRole (cluster-wide exec permissions)
    if resource == "clusterroles":
        return "CRITICAL"

    # High for namespaced Role (namespace-scoped exec permissions)
    return "HIGH"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])

    # Extract only the rules that grant pods/exec
    exec_rules = []
    for rule_entry in rules:
        if "pods/exec" in rule_entry.get("resources", []):
            exec_rules.append(rule_entry)

    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": event.udm("name"),
            "role_type": event.udm("resource"),
            "exec_rules": exec_rules,
        },
    )
