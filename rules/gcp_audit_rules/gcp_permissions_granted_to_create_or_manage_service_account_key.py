from panther_base_helpers import deep_walk

SERVICE_ACCOUNT_MANAGE_ROLES = [
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
]


def rule(event):
    if "SetIAMPolicy" in event.deep_get("protoPayload", "methodName", default=""):
        role = event.deep_walk(
            "protoPayload",
            "serviceData",
            "policyDelta",
            "bindingDeltas",
            "role",
            default="",
            return_val="last",
        )
        action = event.deep_walk(
            "protoPayload",
            "serviceData",
            "policyDelta",
            "bindingDeltas",
            "action",
            default="",
            return_val="last",
        )
        return role in SERVICE_ACCOUNT_MANAGE_ROLES and action == "ADD"
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    target = event.deep_get("resource", "labels", "email_id") or event.deep_get(
        "resource", "labels", "project_id", default="<TARGET_NOT_FOUND>"
    )
    return (
        f"GCP: [{actor}] granted permissions to create or manage service account keys to [{target}]"
    )


def alert_context(event):
    return {
        "resource": event.get("resource"),
        "serviceData": event.deep_get("protoPayload", "serviceData"),
    }
