from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if event.deep_get("protoPayload", "response", "status") == "Failure":
        return False

    if event.deep_get("protoPayload", "methodName") != "io.k8s.core.v1.services.create":
        return False

    if event.deep_get("protoPayload", "request", "spec", "type") != "NodePort":
        return False

    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
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
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created NodePort service in project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    request_spec = event.deep_walk("protoPayload", "request", "spec")
    context["request_spec"] = request_spec
    return context
