from panther_base_helpers import deep_get


def rule(event):
    if event.get("severity", "") == "ERROR":
        if deep_get(event, "protoPayload", "status", "code") == 7:
            details = deep_get(event, "protoPayload", "status", "details", default=[])
            for detail in details:
                violations = deep_get(detail, "violations", default=[])
                for violation in violations:
                    if violation.get("type", "") == "VPC_SERVICE_CONTROLS":
                        return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    method = deep_get(event, "protoPayload", "methodName", default="<METHOD_NOT_FOUND>")
    return f"GCP: [{actor}] performed a [{method}] request that violates VPC Service Controls"
