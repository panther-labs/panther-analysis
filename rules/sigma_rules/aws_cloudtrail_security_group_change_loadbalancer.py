def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "elasticloadbalancing.amazonaws.com",
            event.deep_get("eventName", default="")
            in ["ApplySecurityGroupsToLoadBalancer", "SetSecurityGroups"],
        ]
    ):
        return True
    return False
