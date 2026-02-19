from typing import Any, Dict

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

        if security_context.get("runAsUser") == 0:
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


def get_pod_name(event: Any, default: str = "<UNKNOWN_POD>") -> str:
    """Extract pod name from event with fallbacks for creation events.

    For pod creation events, the name may not be in objectRef (only generateName),
    so we check responseObject.metadata.name where the actual assigned name appears.

    Args:
        event: The event object
        default: Default value if name not found

    Returns:
        Pod name string
    """
    # Try objectRef.name first (works for most operations)
    name = event.udm("name")
    if name:
        return name

    # For creation events, check responseObject.metadata.name
    response_object = event.udm("responseObject") or {}
    name = response_object.get("metadata", {}).get("name")
    if name:
        return name

    # Fallback to requestObject.metadata.name
    request_object = event.udm("requestObject") or {}
    name = request_object.get("metadata", {}).get("name")
    if name:
        return name

    return default


def _extract_container_summary(container: Dict[str, Any]) -> Dict[str, Any]:
    """Extract summary info for a single container.

    Args:
        container: Container specification dictionary

    Returns:
        Dictionary with container details
    """
    env_vars = []
    secret_refs = []
    for env_var in container.get("env", []):
        env_name = env_var.get("name")
        if env_name:
            env_vars.append(env_name)
            value_from = env_var.get("valueFrom", {})
            if "secretKeyRef" in value_from:
                secret_refs.append(
                    {
                        "env_var": env_name,
                        "secret_name": value_from["secretKeyRef"].get("name"),
                        "secret_key": value_from["secretKeyRef"].get("key"),
                    }
                )

    return {
        "name": container.get("name"),
        "image": container.get("image"),
        "ports": [p.get("containerPort") for p in container.get("ports", [])],
        "env_vars": env_vars,
        "secret_refs": secret_refs if secret_refs else None,
        "volume_mounts": [
            {"path": vm.get("mountPath"), "name": vm.get("name")}
            for vm in container.get("volumeMounts", [])
            if vm.get("mountPath") and vm.get("name")
        ],
        "security_context": container.get("securityContext", {}),
        "resources": container.get("resources", {}),
    }


def _extract_volume_info(volume: Dict[str, Any]) -> Dict[str, Any]:
    """Extract info for a single volume.

    Args:
        volume: Volume specification dictionary

    Returns:
        Dictionary with volume details
    """
    vol_info = {"name": volume.get("name")}
    if "hostPath" in volume:
        vol_info["type"] = "hostPath"
        path = volume["hostPath"].get("path")
        vol_info["path"] = path
        vol_info["sensitive"] = is_sensitive_hostpath(path) if path else False
    elif "configMap" in volume:
        vol_info["type"] = "configMap"
        vol_info["source"] = volume["configMap"].get("name")
    elif "secret" in volume:
        vol_info["type"] = "secret"
        vol_info["source"] = volume["secret"].get("secretName")
    else:
        vol_info["type"] = "other"
        vol_info["keys"] = list(volume.keys())
    return vol_info


def get_pod_context_fields(event: Any) -> Dict[str, Any]:
    """Extract enriched pod context for alert_context in pod-related rules.

    Works across EKS, AKS, and GKE via the requestObject UDM field.
    Includes container images, owner references (to identify the controlling workload),
    ports, environment variable names (with secret references flagged), volume mounts,
    security contexts, resources, and pod-level host settings.

    Args:
        event: The event object

    Returns:
        Dictionary with pod metadata and per-container details
    """
    request_object = event.udm("requestObject") or {}
    pod_metadata = request_object.get("metadata", {})
    pod_spec = request_object.get("spec", {})

    # Extract container summaries
    containers = event.udm("containers") or []
    container_summaries = [_extract_container_summary(c) for c in containers]

    # Extract owner references
    owner_refs = [
        {"kind": ref.get("kind"), "name": ref.get("name")}
        for ref in pod_metadata.get("ownerReferences", [])
    ]

    # Extract volumes
    volumes = [_extract_volume_info(v) for v in pod_spec.get("volumes", [])]

    return {
        "pod_name": get_pod_name(event),
        "owner_references": owner_refs if owner_refs else None,
        "host_settings": {
            "hostPID": pod_spec.get("hostPID", False),
            "hostIPC": pod_spec.get("hostIPC", False),
            "hostNetwork": pod_spec.get("hostNetwork", False),
        },
        "containers": container_summaries if container_summaries else None,
        "volumes": volumes if volumes else None,
    }
