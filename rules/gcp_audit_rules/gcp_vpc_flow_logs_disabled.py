def rule(event):
    return all(
        [
            event.get("protoPayload"),
            event.deep_get("protoPayload", "methodName", default="")
            == "v1.compute.subnetworks.patch",
            event.deep_get("protoPayload", "request", "enableFlowLogs") is False,
        ]
    )


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    return f"GCP: [{actor}] disabled VPC Flow Logs for [{resource}]"
