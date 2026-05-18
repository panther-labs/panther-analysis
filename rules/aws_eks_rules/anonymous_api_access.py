import ipaddress

from panther_aws_helpers import eks_panther_obj_ref

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_rfc1918(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in RFC1918_NETWORKS)


def rule(event):
    src_ip = event.get("sourceIPs", ["0.0.0.0"])  # nosec
    if src_ip == ["127.0.0.1"]:
        return False
    if event.get("userAgent", "") == "ELB-HealthChecker/2.0" and _is_rfc1918(src_ip[0]):
        return False

    # Check if the username is set to "system:anonymous", which indicates anonymous access
    if event.deep_get("user", "username") == "system:anonymous":
        return True
    return False


def title(event):
    # For INFO-level events, just group them all together since they're not that interesting
    if severity(event) == "INFO":
        return "Failed Annonymous EKS Acces Attempt(s) Detected"
    p_eks = eks_panther_obj_ref(event)
    return (
        f"Anonymous API access detected on Kubernetes API server "
        f"from [{p_eks.get('sourceIPs')[0]}] to [{event.get('requestURI', 'NO_URI')}] "
        f"on [{p_eks.get('p_source_label')}]"
    )


def severity(event):
    if event.deep_get("annotations", "authorization.k8s.io/decision") != "allow":
        return "INFO"
    if event.get("requestURI") == "/version":
        return "INFO"
    return "DEFAULT"


def dedup(event):
    # For INFO-level events, just group them all together since they're not that interesting
    if severity(event) == "INFO":
        return "no dedup"
    p_eks = eks_panther_obj_ref(event)
    return f"anonymous_access_{p_eks.get('p_source_label')}_{event.get('userAgent')}"


def alert_context(event):
    p_eks = eks_panther_obj_ref(event)
    mutable_event = event.to_dict()
    mutable_event["p_eks"] = p_eks
    return dict(mutable_event)
