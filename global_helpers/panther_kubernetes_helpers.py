from panther_base_helpers import pantherflow_investigation

SYSTEM_NAMESPACES = {"kube-system", "gke-system", "kube-node-lease", "kube-public"}

SENSITIVE_HOSTPATHS = {
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/etc/kubernetes",
    "/etc/",
    "/",
    "/proc",
    "/sys",
    "/root",
    "/home/admin",
    "/var/run/docker.sock",
    "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock",
}

SYSTEM_IDENTITY_PREFIXES = [
    ".iam.gserviceaccount.com",
    "system:serviceaccount:kube-system:",
    "eks:",
    "masterclient",
    "gke-",
    "azure-",
]


def k8s_alert_context(event, extra_fields=None):
    """Generate standard Kubernetes alert context.

    Args:
        event: The event object
        extra_fields: Optional dictionary of additional fields to include

    Returns:
        Dictionary with standard K8s alert context fields
    """
    context = {
        "username": event.udm("username"),
        "sourceIPs": event.udm("sourceIPs"),
        "userAgent": event.udm("userAgent"),
        "namespace": event.udm("namespace"),
        "verb": event.udm("verb"),
        "resource": event.udm("resource"),
        "requestURI": event.udm("requestURI"),
        "responseStatus": event.udm("responseStatus"),
        "cluster": event.get("p_source_label"),
        "PantherFlow Investigation": pantherflow_investigation(event),
    }

    if extra_fields:
        context.update(extra_fields)

    return context


def is_system_namespace(namespace):
    """Check if namespace is a system namespace where privileged operations are expected.

    Args:
        namespace: The namespace string to check

    Returns:
        Boolean indicating if namespace is a system namespace
    """
    if not namespace:
        return False
    return namespace in SYSTEM_NAMESPACES


def is_system_principal(username):
    """Check if username represents a system service account or system component.

    Args:
        username: The username or principal to check

    Returns:
        Boolean indicating if principal is a system account
    """
    if not username:
        return False

    if username.startswith(tuple(SYSTEM_IDENTITY_PREFIXES)):
        return True

    # Azure AKS managed identity service principal
    if username == "masterclient":
        return True

    # Kubernetes system components (not service accounts)
    # Examples: system:kube-controller-manager, system:kube-scheduler, system:node:*
    if username.startswith("system:") and "serviceaccount" not in username:
        return True

    return False


def is_failed_request(response_status):
    """Check if a Kubernetes API request failed.

    Handles both HTTP status codes (EKS/AKS) and gRPC status codes (GCP):
    - HTTP: codes >= 400 indicate failure
    - gRPC: code 0 is success, codes 1-16 are failures

    Args:
        response_status: Response status object from the event

    Returns:
        Boolean indicating if request failed
    """
    if not response_status:
        return False

    status_code = response_status.get("code")
    if not isinstance(status_code, int):
        return False

    # HTTP status codes (EKS/AKS): >= 400 is failure
    if status_code >= 400:
        return True

    # gRPC status codes (GCP): 0 is OK, 1-16 are failures
    # See: https://grpc.github.io/grpc/core/md_doc_statuscodes.html
    if 1 <= status_code <= 16:
        return True

    return False


def is_k8s_log(event):
    """Check if an event is a Kubernetes log across all platforms.

    Validates that the event is from a K8s log source and handles platform-specific checks:
    - EKS: All Amazon.EKS.Audit logs are K8s logs
    - GKE: Checks that GCP.AuditLog has operation.producer == "k8s.io"
    - AKS: Checks that Azure.MonitorActivity has category in ("kube-audit", "kube-audit-admin")

    Args:
        event: The event object

    Returns:
        Boolean indicating if this is a K8s log
    """
    log_type = event.get("p_log_type", "")

    # Check if it's one of the K8s log types
    if log_type not in ("Amazon.EKS.Audit", "Azure.MonitorActivity", "GCP.AuditLog"):
        return False

    # For GCP, verify it's a K8s operation
    if log_type == "GCP.AuditLog":
        return event.deep_get("protoPayload", "serviceName") == "k8s.io"

    # For Azure, verify it's a kube-audit category
    if log_type == "Azure.MonitorActivity":
        category = event.get("category", "")
        return category in ("kube-audit", "kube-audit-admin")

    # For EKS, it's always K8s
    return True


def get_cluster_label(event, default="<UNKNOWN_CLUSTER>"):
    """Extract cluster label from event.

    Args:
        event: The event object
        default: Default value if cluster label not found

    Returns:
        Cluster label string
    """
    return event.get("p_source_label", default)


def is_privileged_container(containers):
    """Check if any container in the list is privileged or runs as root.

    Args:
        containers: List of container specifications

    Returns:
        Boolean indicating if any container is privileged
    """
    if not containers:
        return False

    for container in containers:
        security_context = container.get("securityContext", {})

        if security_context.get("privileged") is True:
            return True

        if security_context.get("runAsNonRoot") is False:
            return True

    return False


def has_hostpath_volume(volumes):
    """Check if any volume is a hostPath volume.

    Args:
        volumes: List of volume specifications

    Returns:
        Boolean indicating if any volume is hostPath type
    """
    if not volumes:
        return False

    for volume in volumes:
        if "hostPath" in volume:
            return True

    return False


def get_hostpath_paths(volumes):
    """Extract all hostPath paths from volume specifications.

    Args:
        volumes: List of volume specifications

    Returns:
        List of hostPath path strings
    """
    if not volumes:
        return []

    paths = []
    for volume in volumes:
        if "hostPath" in volume:
            path = volume.get("hostPath", {}).get("path")
            if path:
                paths.append(path)

    return paths


def is_sensitive_hostpath(path):
    """Check if a hostPath is sensitive (system directories).

    Args:
        path: The hostPath path string

    Returns:
        Boolean indicating if path is sensitive
    """
    if not path:
        return False

    for sensitive_path in SENSITIVE_HOSTPATHS:
        if path == sensitive_path or path.startswith(sensitive_path + "/"):
            return True

    return False


def get_resource_name(event, default="<UNKNOWN>"):
    """Extract resource name from event.

    Args:
        event: The event object
        default: Default value if name not found

    Returns:
        Resource name string
    """
    return event.udm("name") or default
