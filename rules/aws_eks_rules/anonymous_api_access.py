from panther_aws_helpers import eks_panther_obj_ref


def rule(event):
    src_ip = event.get("sourceIPs", ["0.0.0.0"])  # nosec
    if src_ip == ["127.0.0.1"]:
        return False
    if event.get("userAgent", "") == "ELB-HealthChecker/2.0" and src_ip[0].startswith("10.0."):
        return False

    # Check if the username is set to "system:anonymous", which indicates anonymous access
    if event.deep_get("user", "username") == "system:anonymous":
        return True
    return False


def title(event):
    # For INFO-level events, just group them all together since they're not that interesting
    if event.deep_get("annotations", "authorization.k8s.io/decision") != "allow":
        return "Failed Anonymous EKS Access Attempt(s) Detected"
    if event.get("requestURI") == "/version":
        return "Anonymous EKS Access to /version Endpoint Detected"
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
