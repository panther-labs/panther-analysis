from panther_base_helpers import deep_get


def rule(event):
    return all(
        [
            event.get("protoPayload"),
            deep_get(event, "protoPayload", "methodName", default="")
            == "v1.compute.subnetworks.patch",
            deep_get(event, "protoPayload", "request", "enableFlowLogs") is False,
        ]
    )


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    return f"GCP: [{actor}] disabled VPC Flow Logs for [{resource}]"
