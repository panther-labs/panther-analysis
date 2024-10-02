def rule(event):
    severity = event.deep_get("severity", default="")
    status_code = event.deep_get("protoPayload", "status", "code", default="")
    violation_types = event.deep_walk(
        "protoPayload", "status", "details", "violations", "type", default=[]
    )
    if all(
        [
            severity == "ERROR",
            status_code == 7,
            "VPC_SERVICE_CONTROLS" in violation_types,
        ]
    ):
        return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    method = event.deep_get("protoPayload", "methodName", default="<METHOD_NOT_FOUND>")
    return f"GCP: [{actor}] performed a [{method}] request that violates VPC Service Controls"
