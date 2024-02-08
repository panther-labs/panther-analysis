from ipaddress import ip_address

from panther_base_helpers import deep_get, eks_panther_obj_ref

# Explicitly ignore eks:node-manager and eks:addon-manager
#  which are run as Lambdas and originate from public IPs
AMZ_PUBLICS = {"eks:addon-manager", "eks:node-manager"}


# Alert if
#   the username starts ( with system: or eks: )
#   and
#   sourceIPs[0] is a Public Address
def rule(event):
    if event.get("stage", "") != "ResponseComplete":
        return False
    # We explicitly ignore 403 here. There is another
    #  detection that monitors for 403 volume-by-originating-ip
    if event.get("responseStatus", {}).get("code", 0) == 403:
        return False
    p_eks = eks_panther_obj_ref(event)
    if (
        p_eks.get("actor") in AMZ_PUBLICS
        and ":assumed-role/AWSWesleyClusterManagerLambda"
        in deep_get(event, "user", "extra", "arn", default=["not found"])[0]
    ):
        return False
    if (
        p_eks.get("actor").startswith("system:") or p_eks.get("actor").startswith("eks:")
    ) and not ip_address(p_eks.get("sourceIPs")[0]).is_private:
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
