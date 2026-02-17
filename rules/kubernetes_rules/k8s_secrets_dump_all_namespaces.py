from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

# System components that legitimately list all secrets cluster-wide
ALLOWED_SECRET_LISTERS = {
    "system:serviceaccount:kube-system:namespace-controller",
    "system:serviceaccount:kube-system:kube-state-metrics",
    "system:apiserver",
}


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    namespace = event.udm("namespace")
    username = event.udm("username") or ""
    response_status = event.udm("responseStatus")
    request_uri = event.udm("requestURI") or ""

    # Only check secret list operations that are successful
    if verb != "list" or resource != "secrets" or is_failed_request(response_status):
        return False

    # Key indicator: namespace is empty (cluster-wide list, not namespaced)
    # and requestURI doesn't contain /namespaces/ in path
    if namespace or (request_uri and "/namespaces/" in request_uri):
        return False

    # Exclude system principals and specific components
    if is_system_principal(username) or username in ALLOWED_SECRET_LISTERS:
        return False

    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    request_uri = event.udm("requestURI") or ""

    return f"[{username}] dumped all secrets across all namespaces (URI: {request_uri})"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    return f"k8s_secrets_dump_{username}"


def alert_context(event):
    request_uri = event.udm("requestURI") or ""

    # Extract query parameters if present (e.g., limit=500)
    query_params = {}
    if "?" in request_uri:
        query_string = request_uri.split("?", 1)[1]
        for param in query_string.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                query_params[key] = value

    return k8s_alert_context(
        event,
        extra_fields={
            "request_uri": request_uri,
            "query_parameters": query_params,
            "operation": "list_all_secrets",
        },
    )
