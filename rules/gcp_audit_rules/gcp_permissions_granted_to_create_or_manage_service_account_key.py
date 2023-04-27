from panther_base_helpers import deep_get

SERVICE_ACCOUNT_MANAGE_ROLES = [
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
]


def rule(event):
    if "SetIAMPolicy" in deep_get(event, "protoPayload", "methodName", default=""):
        binding_deltas = deep_get(
            event, "protoPayload", "serviceData", "policyDelta", "bindingDeltas", default=[{}]
        )
        for binding_delta in binding_deltas:
            if all(
                [
                    binding_delta.get("role", "") in SERVICE_ACCOUNT_MANAGE_ROLES,
                    binding_delta.get("action", "") == "ADD",
                ]
            ):
                return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    target = deep_get(event, "resource", "labels", "email_id") or deep_get(
        event, "resource", "labels", "project_id", default="<TARGET_NOT_FOUND>"
    )
    return (
        f"GCP: [{actor}] granted permissions to create or manage service account keys to [{target}]"
    )


def alert_context(event):
    return {
        "resource": deep_get(event, "resource"),
        "serviceData": deep_get(event, "protoPayload", "serviceData"),
    }
