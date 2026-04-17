from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if not event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND").endswith(
        "ApiKeys.CreateKey"
    ):
        return False

    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if auth.get("permission") == "serviceusage.apiKeys.create" and auth.get("granted") is True:
            return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created new API Key in project [{project_id}]"


def alert_context(event):
    return gcp_alert_context(event)
