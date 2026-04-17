import re


def get_info(event):
    fields = {
        "principal": "protoPayload.authenticationInfo.principalEmail",
        "project_id": "protoPayload.resource.labels.project_id",
        "caller_ip": "protoPayload.requestMetadata.callerIP",
        "user_agent": "protoPayload.requestMetadata.callerSuppliedUserAgent",
        "method_name": "protoPayload.methodName",
    }
    return {name: event.deep_get(*(path.split("."))) for name, path in fields.items()}


def get_k8s_info(event):
    """
    Get GCP K8s info such as pod, authorized user etc.
    return a tuple of strings
    """
    pod_slug = event.deep_get("protoPayload", "resourceName")
    # core/v1/namespaces/<namespace>/pods/<pod-id>/<action>
    _, _, _, namespace, _, pod, _ = pod_slug.split("/")
    return get_info(event) | {"namespace": namespace, "pod": pod}


def get_flow_log_info(event):
    fields = {
        "src_ip": "jsonPayload.connection.src_ip",
        "dest_ip": "jsonPayload.connection.dest_ip",
        "src_port": "jsonPayload.connection.src_port",
        "dest_port": "jsonPayload.connection.dest_port",
        "protocol": "jsonPayload.connection.protocol",
        "bytes_sent": "jsonPayload.bytes_sent",
        "reporter": "jsonPayload.reporter",
    }
    return {name: event.deep_get(*(path.split("."))) for name, path in fields.items()}


def gcp_alert_context(event):
    return {
        "project": event.deep_get("resource", "labels", "project_id", default=""),
        "principal": event.deep_get(
            "protoPayload", "authenticationInfo", "principalEmail", default=""
        ),
        "caller_ip": event.deep_get("protoPayload", "requestMetadata", "callerIP", default=""),
        "methodName": event.deep_get("protoPayload", "methodName", default=""),
        "resourceName": event.deep_get("protoPayload", "resourceName", default=""),
        "serviceName": event.deep_get("protoPayload", "serviceName", default=""),
    }


def get_binding_deltas(event):
    """A GCP helper function to return the binding deltas from audit events

    Binding deltas provide context on a permission change, including the
    action, role, and member associated with the request.
    """
    if event.get("protoPayload", {}).get("methodName") != "SetIamPolicy":
        return []

    service_data = event.get("protoPayload", {}).get("serviceData")
    if not service_data:
        return []

    binding_deltas = service_data.get("policyDelta", {}).get("bindingDeltas")
    if not binding_deltas:
        return []
    return binding_deltas


# GKE/K8s Security Exclusions
# Well-known GCP service accounts that legitimately perform privileged operations
# Reference: https://cloud.google.com/kubernetes-engine/docs/concepts/service-accounts
# Reference:
# https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_pod_creation
#
# SECURITY NOTE: These patterns must be as specific as possible to prevent attackers
# from creating accounts that match these patterns. Use full prefixes and suffixes where possible.
GKE_SYSTEM_SERVICE_ACCOUNT_PREFIXES = [
    # Kubernetes system accounts (exact match)
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:addon-manager",
    "system:serviceaccount:kube-system:",
    "system:serviceaccount:kube-public:",
    "system:serviceaccount:kube-node-lease:",
    "system:serviceaccount:gke-system:",
    "system:serviceaccount:gke-managed-system:",
    "system:serviceaccount:gmp-system:",
    "system:serviceaccount:gmp-public:",
    "system:serviceaccount:config-management-system:",
    "system:serviceaccount:istio-system:",
    "system:serviceaccount:asm-system:",
]

# GCP project-specific service account patterns that require regex matching
# These will be matched against the full email pattern
GKE_SYSTEM_SERVICE_ACCOUNT_PATTERNS = [
    # GKE service accounts - must be in a numeric project ID
    re.compile(r"^[\d]+-compute@developer\.gserviceaccount\.com$"),
    re.compile(r"^container-engine-robot@.*\.iam\.gserviceaccount\.com$"),
    re.compile(r"^gke-[\d]+@.*\.iam\.gserviceaccount\.com$"),
    # GCP managed service accounts
    re.compile(r"^service-[\d]+@container-engine-robot\.iam\.gserviceaccount\.com$"),
    re.compile(r"^service-[\d]+@containerregistry\.iam\.gserviceaccount\.com$"),
    re.compile(r"^[\d]+@cloudservices\.gserviceaccount\.com$"),
    # Workload identity service accounts
    re.compile(r"^.*\.svc\.id\.goog\[kube-system/.*\]$"),
    re.compile(r"^.*\.svc\.id\.goog\[gke-system/.*\]$"),
    re.compile(r"^.*\.svc\.id\.goog\[gke-managed-system/.*\]$"),
]

# System namespaces where privileged pods are expected
# Reference: https://cloud.google.com/kubernetes-engine/docs/concepts/namespaces
# Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/
GKE_SYSTEM_NAMESPACES = [
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "gke-system",
    "gke-managed-system",
    "gmp-system",  # Google Managed Prometheus
    "gmp-public",
    "config-management-system",  # Anthos Config Management
    "istio-system",  # Istio service mesh
    "asm-system",  # Anthos Service Mesh
]


def is_gke_system_principal(principal_email):
    """Check if the actor is a well-known GKE/GCP system service account.

    This function uses strict pattern matching to prevent false negatives where
    an attacker might create an account with system-like names
    (e.g., "kubernetes-attacker@evil.com").

    Args:
        principal_email: The email/identifier of the principal performing the action

    Returns:
        bool: True if this is a known system service account, False otherwise

    Reference: https://cloud.google.com/iam/docs/service-accounts#default

    Security Note: This function uses exact prefix matching and regex patterns to ensure
    only legitimate GCP/GKE service accounts are excluded, preventing attackers from
    bypassing detection by including system keywords in their account names.
    """
    if not principal_email:
        return False

    # Check for exact prefix matches (Kubernetes system accounts)
    for prefix in GKE_SYSTEM_SERVICE_ACCOUNT_PREFIXES:
        if principal_email.startswith(prefix):
            return True

    # Check for exact matches against regex patterns (GCP service accounts)
    for pattern in GKE_SYSTEM_SERVICE_ACCOUNT_PATTERNS:
        if pattern.match(principal_email):
            return True

    return False


def is_gke_system_namespace(resource_name):
    """Check if a K8s resource is in a GKE system namespace.

    System namespaces are managed by GKE and typically require privileged access
    for core Kubernetes functionality.

    Args:
        resource_name: The full resource name from the GCP audit log
                      (e.g., "core/v1/namespaces/kube-system/pods/my-pod")

    Returns:
        bool: True if the resource is in a system namespace, False otherwise
    """
    if not resource_name:
        return False

    # Extract namespace from resource name (format: core/v1/namespaces/<namespace>/...)
    parts = resource_name.split("/")
    if len(parts) >= 4 and parts[2] == "namespaces":
        namespace = parts[3]
        return namespace in GKE_SYSTEM_NAMESPACES
    return False
