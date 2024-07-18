from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get, deep_walk


def rule(event):
    if deep_get(event, "severity") == "ERROR":
        return False

    if not deep_get(event, "protoPayload", "methodName", default="").endswith("Services.SetIamPolicy"):
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if auth.get("permission") == "run.services.setIamPolicy" and auth.get("granted") is True:
            return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = deep_get(event, "resource", "resourceName", default="<RESOURCE_NOT_FOUND>")
    assigned_role = deep_walk(event, "protoPayload", "response", "bindings", "role")
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] was granted access to [{resource}] service with "
        f"the [{assigned_role}] role in project [{project_id}]"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    context["assigned_role"] = deep_walk(
        event,
        "protoPayload",
        "response",
        "bindings",
        "role",
    )
    return context
