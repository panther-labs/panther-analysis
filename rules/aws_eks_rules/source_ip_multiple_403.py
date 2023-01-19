from ipaddress import ip_address

from panther_base_helpers import eks_panther_obj_ref


# Alert if
#   state is ResponseComplete
#   sourceIPs[0] is a Public Address
#   responseStatus:code == 403
def rule(event):
    if event.get("stage", "") != "ResponseComplete":
        return False
    # We include only 403
    if event.get("responseStatus", {}).get("code", 0) != 403:
        return False
    # And we only want things that might naively be kubernetes api endpoints
    # we do not want to alert on scanners casting non-kubernetes requests.
    if not event.get('requestURI', '').startswith(('/api/', '/apis/')):
        return False
    p_eks = eks_panther_obj_ref(event)
    if ip_address(p_eks.get("sourceIPs")[0]).is_private:
        return False
    return True


# If not defined, defaults to the rule display name or rule ID.
def title(event):
    p_eks = eks_panther_obj_ref(event)
    return (
        f"[{p_eks.get('sourceIPs')[0]}] received [403] "
        f"when executing [{p_eks.get('verb')}] "
        f"for resource [{p_eks.get('resource')}] "
        f"in ns [{p_eks.get('ns')}] on "
        f"[{p_eks.get('p_source_label')}] as "
        f"[{p_eks.get('actor')}]"
    )


def dedup(event):
    p_eks = eks_panther_obj_ref(event)
    return f"{p_eks.get('p_source_label')}_403_{p_eks.get('sourceIPs')[0]}"


def alert_context(event):
    p_eks = eks_panther_obj_ref(event)
    mutable_event = event.to_dict()
    mutable_event["p_eks"] = p_eks
    return dict(mutable_event)
