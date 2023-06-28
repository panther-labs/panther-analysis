from panther_base_helpers import deep_get, deep_walk


def rule(event):
    severity = deep_get(event, "severity", default="")
    status_code = deep_get(event, "protoPayload", "status", "code", default="")
    violations = deep_walk(event, "protoPayload", "status", "details", "violations", "type", default="")
    if severity == "ERROR" and status_code == 7:
        if "VPC_SERVICE_CONTROLS" in violations:
            return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    method = deep_get(event, "protoPayload", "methodName", default="<METHOD_NOT_FOUND>")
    return f"GCP: [{actor}] performed a [{method}] request that violates VPC Service Controls"
