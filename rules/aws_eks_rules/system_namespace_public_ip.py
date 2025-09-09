from ipaddress import ip_address

from panther_aws_helpers import eks_panther_obj_ref
from panther_ipinfo_helpers import get_ipinfo_asn
from panther_misp_helpers import get_misp_warning_lists

# Explicitly ignore eks:node-manager and eks:addon-manager
#  which are run as Lambdas and originate from public IPs
AMZ_PUBLICS = {"eks:addon-manager", "eks:node-manager"}


def is_aws_infrastructure_ip(event):
    """Check if the source IP is from AWS infrastructure based on enrichment data."""
    p_eks = eks_panther_obj_ref(event)
    source_ip = p_eks.get("sourceIPs", [None])[0]

    if not source_ip:
        return False

    # Check MISP warning lists for AWS IP ranges
    misp_data = get_misp_warning_lists(event)
    if misp_data and misp_data.has_warning_list_id(source_ip, "amazon-aws"):
        return True

    # Check ipinfo ASN for Amazon using helper class
    ipinfo_asn_data = get_ipinfo_asn(event)
    if ipinfo_asn_data:
        asn_value = ipinfo_asn_data.asn("sourceIPs")[0]
        domain_value = ipinfo_asn_data.domain("sourceIPs")[0]
        if asn_value == "AS16509" and domain_value == "amazon.com":
            return True

    return False


def is_legitimate_eks_node(event):
    """Check if this is a legitimate EKS node based on username and user groups."""
    p_eks = eks_panther_obj_ref(event)
    actor = p_eks.get("actor", "")

    # Check if it's a system node
    if actor.startswith("system:node:"):
        user_groups = event.deep_get("user", "groups", default=[])
        # Legitimate EKS nodes should be in system:nodes and system:authenticated groups
        return "system:nodes" in user_groups and "system:authenticated" in user_groups

    return False


# Alert if
#   the username starts ( with system: or eks: )
#   and
#   sourceIPs[0] is a Public Address
#   but exclude legitimate EKS nodes from AWS infrastructure IPs
def rule(event):
    if event.get("stage", "") != "ResponseComplete":
        return False
    # We explicitly ignore 403 here. There is another
    #  detection that monitors for 403 volume-by-originating-ip
    if event.get("responseStatus", {}).get("code", 0) == 403:
        return False

    p_eks = eks_panther_obj_ref(event)

    # Ignore AWS managed services (addon-manager, node-manager)
    if (
        p_eks.get("actor") in AMZ_PUBLICS
        and ":assumed-role/AWSWesleyClusterManagerLambda"
        in event.deep_get("user", "extra", "arn", default=["not found"])[0]
    ):
        return False

    if is_legitimate_eks_node(event) and is_aws_infrastructure_ip(event):
        return False

    # Check if this is a system or EKS user from a public IP
    actor = p_eks.get("actor", "")
    if (actor.startswith("system:") or actor.startswith("eks:")) and ip_address(
        p_eks.get("sourceIPs")[0]
    ).is_global:
        return True

    return False


# If not defined, defaults to the rule display name or rule ID.
def title(event):
    p_eks = eks_panther_obj_ref(event)
    return (
        f"[{p_eks.get('actor')}] executed [{p_eks.get('verb')}] "
        f"for resource [{p_eks.get('resource')}] "
        f"in ns [{p_eks.get('ns')}] on "
        f"[{p_eks.get('p_source_label')}] from "
        f"[{p_eks.get('sourceIPs')[0]}]"
    )


def dedup(event):
    p_eks = eks_panther_obj_ref(event)
    return f"{p_eks.get('p_source_label')}_eks_system_namespace_{p_eks.get('sourceIPs')[0]}"


def alert_context(event):
    p_eks = eks_panther_obj_ref(event)
    mutable_event = event.to_dict()
    mutable_event["p_eks"] = p_eks
    return dict(mutable_event)
