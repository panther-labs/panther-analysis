from panther_aws_helpers import eks_panther_obj_ref


def rule(event):
    # Check if the username is set to "system:anonymous", which indicates anonymous access
    p_eks = eks_panther_obj_ref(event)
    if p_eks.get("actor") == "system:anonymous":
        return True
    return False


def title(event):
    p_eks = eks_panther_obj_ref(event)
    return (
        f"Anonymous API access detected on Kubernetes API server "
        f"from [{p_eks.get('sourceIPs')[0]}] to [{p_eks.get('resource')}] "
        f"in namespace [{p_eks.get('ns')}] on [{p_eks.get('p_source_label')}]"
    )


def dedup(event):
    p_eks = eks_panther_obj_ref(event)
    return f"anonymous_access_{p_eks.get('p_source_label')}_{p_eks.get('sourceIPs')[0]}"


def alert_context(event):
    p_eks = eks_panther_obj_ref(event)
    mutable_event = event.to_dict()
    mutable_event["p_eks"] = p_eks
    return dict(mutable_event)
