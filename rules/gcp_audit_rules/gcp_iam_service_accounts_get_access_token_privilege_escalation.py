from gcp_base_helpers import gcp_alert_context


def rule(event):
    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if (
            auth.get("permission") == "iam.serviceAccounts.getAccessToken"
            and auth.get("granted") is True
        ):
            return True
    return False


def title(event):
    actor = event.udm("actor_user")
    operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"


def alert_context(event):
    return gcp_alert_context(event)
