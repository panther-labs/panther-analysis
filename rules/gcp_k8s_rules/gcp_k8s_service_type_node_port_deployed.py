from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get, deep_walk


def rule(event):
    if deep_get(event, "protoPayload", "response", "status") == "Failure":
        return False

    if deep_get(event, "protoPayload", "methodName") != "io.k8s.core.v1.services.create":
        return False

    if deep_get(event, "protoPayload", "request", "spec", "type") != "NodePort":
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if (
            auth.get("permission") == "io.k8s.core.v1.services.create"
            and auth.get("granted") is True
        ):
            return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created NodePort service in project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    request_spec = deep_walk(event, "protoPayload", "request", "spec")
    context["request_spec"] = request_spec
    return context
