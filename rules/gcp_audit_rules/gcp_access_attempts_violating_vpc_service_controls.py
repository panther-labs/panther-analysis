from panther_base_helpers import deep_get, deep_walk


def rule(event):
    if event.get("severity", "") == "ERROR":
        if deep_get(event, "protoPayload", "status", "code") == 7:
            return (
                deep_walk(event, "protoPayload", "status", "details", "violations", "type")
                == "VPC_SERVICE_CONTROLS"
            )
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    method = deep_get(event, "protoPayload", "methodName", default="<METHOD_NOT_FOUND>")
    return f"GCP: [{actor}] performed a [{method}] request that violates VPC Service Controls"
