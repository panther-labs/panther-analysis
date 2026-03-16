from ipaddress import ip_address

from panther_ipinfo_helpers import get_ipinfo_asn
from panther_kubernetes_helpers import k8s_alert_context

# AWS-managed services that run as Lambdas and legitimately originate from public IPs
AWS_MANAGED_PRINCIPALS = {"eks:addon-manager", "eks:node-manager"}

# AKS-managed service accounts that legitimately make requests from public IPs
# These are CSI drivers and system controllers that run on nodes with public IPs
AKS_MANAGED_SERVICE_ACCOUNTS = {
    "system:serviceaccount:kube-system:csi-azuredisk-node-sa",
    "system:serviceaccount:kube-system:csi-azurefile-node-sa",
    "system:serviceaccount:kube-system:csi-secrets-store-provider-azure",
    "system:serviceaccount:kube-system:cloud-node-manager",
}

# Cloud provider ASN mappings for infrastructure IP detection
CLOUD_PROVIDER_ASNS = {
    "aws": ["AS16509"],
    "azure": ["AS8075"],
    "gcp": ["AS15169", "AS396982"],
}

# GKE control plane user agents that legitimately make anonymous requests from Google IPs
GKE_SYSTEM_USER_AGENTS = {
    "GoogleKubernetesEngineFrontend",
    "GoogleHC/1.0",
}

# GKE health check endpoints accessed by control plane
GKE_HEALTH_CHECK_ENDPOINTS = {"readyz", "livez", "healthz"}


def is_cloud_infrastructure_ip(event, cloud_provider):
    """Check if source IP is from cloud provider infrastructure using IPInfo ASN."""
    ipinfo_asn_data = get_ipinfo_asn(event)
    if not ipinfo_asn_data:
        return False

    # Get ASN from appropriate field based on log type
    log_type = event.get("p_log_type", "")
    if "GCP" in log_type:
        asn_value = ipinfo_asn_data.asn("callerIp")
    else:
        asn_value = ipinfo_asn_data.asn("sourceIPs")

    if (
        asn_value
        and len(asn_value) > 0
        and asn_value[0] in CLOUD_PROVIDER_ASNS.get(cloud_provider, [])
    ):
        return True

    return False


def _is_legitimate_eks_node(event):
    """Check if this is a legitimate EKS node based on username and user groups."""
    username = event.udm("username") or ""

    # Check if it's a system node
    if username.startswith("system:node:"):
        user_groups = event.deep_get("user", "groups", default=[])
        # Legitimate EKS nodes should be in system:nodes and system:authenticated groups
        return "system:nodes" in user_groups and "system:authenticated" in user_groups

    return False


def is_aws_managed_service(event):
    """Check if this is an AWS-managed EKS service like addon-manager or node-manager."""
    username = event.udm("username") or ""

    if username not in AWS_MANAGED_PRINCIPALS:
        return False

    # Verify it's actually from AWS Lambda (AWSWesleyClusterManagerLambda role)
    arn = event.deep_get("user", "extra", "arn", default=[""])[0]
    return ":assumed-role/AWSWesleyClusterManagerLambda" in arn


def _is_legitimate_eks_request(event):
    """Check if this is a legitimate EKS request."""
    if is_aws_managed_service(event):
        return True
    return _is_legitimate_eks_node(event) and is_cloud_infrastructure_ip(event, "aws")


def _is_legitimate_aks_request(event, username):
    """Check if this is a legitimate AKS request."""
    if username in AKS_MANAGED_SERVICE_ACCOUNTS:
        return True
    return username.startswith("system:node:") and is_cloud_infrastructure_ip(event, "azure")


def _is_legitimate_gke_request(event, username):
    """Check if this is a legitimate GKE request."""
    if username.startswith("system:node:") and is_cloud_infrastructure_ip(event, "gcp"):
        return True

    # GKE control plane makes anonymous health check requests from Google IPs
    if username == "system:anonymous":
        user_agent = event.deep_get(
            "protoPayload", "requestMetadata", "callerSuppliedUserAgent", default=""
        )
        if user_agent not in GKE_SYSTEM_USER_AGENTS:
            return False

        # Prefer ASN-based verification
        if is_cloud_infrastructure_ip(event, "gcp"):
            return True

        # Fallback: Health check endpoints are legitimate without ASN verification
        resource_name = event.deep_get("protoPayload", "resourceName", default="")
        request_uri = event.udm("requestURI") or ""

        # Use path-based matching to avoid false positives
        return any(
            f"/{endpoint}" in resource_name
            or resource_name.endswith(endpoint)
            or f"/{endpoint}" in request_uri
            or request_uri.endswith(endpoint)
            for endpoint in GKE_HEALTH_CHECK_ENDPOINTS
        )

    return False


def _is_legitimate_cloud_node(event, username, log_type):
    """Check if this is a legitimate cloud provider node."""
    if "Amazon.EKS" in log_type:
        return _is_legitimate_eks_request(event)
    if "Azure.MonitorActivity" in log_type:
        return _is_legitimate_aks_request(event, username)
    if "GCP.AuditLog" in log_type:
        return _is_legitimate_gke_request(event, username)
    return False


def rule(event):  # pylint: disable=too-many-return-statements
    username = event.udm("username") or ""
    source_ips = event.udm("sourceIPs") or []
    response_status = event.udm("responseStatus") or {}
    log_type = event.get("p_log_type", "")

    # Only check ResponseComplete stage (EKS/AKS have this field)
    stage = event.get("stage")
    if stage and stage != "ResponseComplete":
        return False

    # Exclude 403 responses (handled by k8s_multiple_403_public_ip rule)
    if response_status.get("code") == 403:
        return False

    # Check if this is a REAL system principal (service accounts, nodes, cloud-managed)
    # Excludes system:anonymous and system:unauthenticated (unauthenticated API access)
    if not (
        username.startswith("system:serviceaccount:")
        or username.startswith("system:node:")
        or username.startswith("eks:")
        or username.startswith("aks:")
    ):
        return False

    # Check if source IP is public
    if not source_ips:
        return False

    # If any source IP is private, this is a pod running on a node (which has both
    # public and private interfaces). Real external attackers only have public IPs.
    for ip_str in source_ips:
        try:
            ip_obj = ip_address(ip_str)
            if not ip_obj.is_global:
                return False
        except ValueError:
            continue  # Skip invalid IPs

    # Exclude legitimate cloud provider nodes
    if _is_legitimate_cloud_node(event, username, log_type):
        return False

    # Alert: system principal accessed from non-cloud-provider public IP
    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    verb = event.udm("verb") or "<UNKNOWN_VERB>"
    resource = event.udm("resource") or "<UNKNOWN_RESOURCE>"
    namespace = event.udm("namespace")
    source_ips = event.udm("sourceIPs") or ["<UNKNOWN_IP>"]
    source_ip = source_ips[0] if source_ips else "<UNKNOWN_IP>"

    # Handle cluster-scoped resources (no namespace)
    if namespace:
        namespace_str = f"in namespace [{namespace}] "
    else:
        namespace_str = "(cluster-scoped) "

    return (
        f"System principal [{username}] executed [{verb}] for resource [{resource}] "
        f"{namespace_str}from non-cloud public IP [{source_ip}]"
    )


def dedup(event):
    source_ips = event.udm("sourceIPs") or ["<UNKNOWN_IP>"]
    source_ip = source_ips[0] if source_ips else "<UNKNOWN_IP>"
    return f"k8s_system_principal_{source_ip}"


def alert_context(event):
    source_ips = event.udm("sourceIPs") or []
    ipinfo_asn_data = get_ipinfo_asn(event)

    extra_fields = {
        "source_ip": source_ips[0] if source_ips else None,
        "asn_info": None,
    }

    # Add ASN information if available
    if ipinfo_asn_data:
        log_type = event.get("p_log_type", "")
        if "GCP" in log_type:
            asn_value = ipinfo_asn_data.asn("callerIp")
            domain_value = ipinfo_asn_data.domain("callerIp")
        else:
            asn_value = ipinfo_asn_data.asn("sourceIPs")
            domain_value = ipinfo_asn_data.domain("sourceIPs")

        if asn_value and asn_value[0]:
            extra_fields["asn_info"] = {
                "asn": asn_value[0],
                "domain": domain_value[0] if domain_value else None,
            }

    return k8s_alert_context(event, extra_fields=extra_fields)
