from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check role/clusterrole creation events
    if verb != "create" or resource not in {"roles", "clusterroles"}:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals to reduce false positives
    if is_system_principal(username):
        return False

    # Check request object for node/proxy permissions
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])

    for rule_config in rules:
        resources = rule_config.get("resources", [])
        verbs = rule_config.get("verbs", [])

        # Check for nodes/proxy or nodes/* permissions
        # These allow accessing the kubelet API through the API server proxy
        if "nodes/proxy" in resources or ("nodes/*" in resources and verbs):
            return True

        # Also check for wildcard on nodes with specific verbs that enable proxy access
        if "nodes" in resources and "*" in resources:
            return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"

    role_type = "ClusterRole" if resource == "clusterroles" else "Role"

    return f"[{username}] created {role_type} [{name}] with node proxy permissions"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    name = event.udm("name") or "<UNKNOWN_ROLE>"
    return f"k8s_node_proxy_{username}_{name}"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    rules = request_object.get("rules", [])

    # Extract rules with node/proxy permissions
    dangerous_rules = []
    for rule_config in rules:
        resources = rule_config.get("resources", [])
        if "nodes/proxy" in resources or "nodes/*" in resources or "nodes" in resources:
            dangerous_rules.append(rule_config)

    return k8s_alert_context(
        event,
        extra_fields={
            "role_name": event.udm("name"),
            "role_type": event.udm("resource"),
            "dangerous_rules": dangerous_rules,
        },
    )
