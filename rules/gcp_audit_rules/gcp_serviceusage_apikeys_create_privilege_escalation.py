from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get, deep_walk


def rule(event):
    if not deep_get(event, "protoPayload", "methodName").endswith("ApiKeys.CreateKey"):
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if (
                auth.get("permission") == "serviceusage.apiKeys.create"
                and auth.get("granted") is True
        ):
            return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created new API Key in project [{project_id}]"


def alert_context(event):
    return gcp_alert_context(event)
