from urllib.parse import unquote

from panther_kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)

# Paths related to service account tokens that attackers target
SERVICE_ACCOUNT_TOKEN_PATHS = {
    # Standard Kubernetes service account token
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount",
    # AWS EKS with IRSA (IAM Roles for Service Accounts)
    "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    "/var/run/secrets/eks.amazonaws.com/serviceaccount",
    # Azure AKS with Workload Identity
    "/var/run/secrets/azure/tokens/azure-identity-token",
    "/var/run/secrets/azure/tokens",
    # GCP GKE with Workload Identity
    "/var/run/secrets/tokens/gcp-ksa/token",
    "/var/run/secrets/tokens/gcp-ksa",
    # Partial path match for various token access patterns
    "serviceaccount/token",
}


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    subresource = event.udm("subresource")
    namespace = event.udm("namespace")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check exec subresource operations
    if verb != "create" or resource != "pods" or subresource != "exec":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals in system namespaces (legitimate operations)
    # but alert on users stealing tokens from system namespaces (malicious)
    if is_system_principal(username) and is_system_namespace(namespace):
        return False

    # Check command in requestObject
    request_object = event.udm("requestObject") or {}
    command = request_object.get("command", [])
    command_str = " ".join(str(cmd) for cmd in command).lower()

    # Check if command references service account token paths
    if any(path.lower() in command_str for path in SERVICE_ACCOUNT_TOKEN_PATHS):
        return True

    # Check requestURI (may contain URL-encoded paths)
    request_uri = event.udm("requestURI") or ""
    # URL decode to handle encoded characters like %2F for /
    decoded_uri = unquote(request_uri).lower()

    if any(path.lower() in decoded_uri for path in SERVICE_ACCOUNT_TOKEN_PATHS):
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"

    return (
        f"[{username}] attempted to steal service account token from pod " f"[{namespace}/{name}]"
    )


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_POD>"
    return f"k8s_steal_token_{username}_{namespace}_{name}"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    command = request_object.get("command", [])
    request_uri = event.udm("requestURI") or ""

    return k8s_alert_context(
        event,
        extra_fields={
            "pod_name": event.udm("name"),
            "command": command,
            "request_uri": request_uri,
            "container": request_object.get("container"),
        },
    )
