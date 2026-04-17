from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if event.get("severity") == "ERROR":
        return False

    method_name = event.deep_get("protoPayload", "methodName", default="")
    if not method_name.endswith("Services.CreateService"):
        return False

    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if auth.get("permission") == "run.services.create" and auth.get("granted") is True:
            return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created new Run Service in project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    context["service_account"] = event.deep_get(
        "protoPayload",
        "request",
        "service",
        "spec",
        "template",
        "spec",
        default="<SERVICE_ACCOUNT_NOT_FOUND>",
    )
    return context
