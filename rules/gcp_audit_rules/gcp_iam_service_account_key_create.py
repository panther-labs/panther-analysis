from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_walk, deep_get


def rule(event):
    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    for auth in authorization_info:
        if (
            auth.get("permission") == "iam.serviceAccountKeys.create"
            and auth.get("granted") is True
        ):
            return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"


def alert_context(event):
    return gcp_alert_context(event)
