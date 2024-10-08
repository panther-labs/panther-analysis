from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if event.get("severity") == "ERROR":
        return False

    method_name = event.deep_get("protoPayload", "methodName", default="")
    if not method_name.endswith("Services.SetIamPolicy"):
        return False

    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if auth.get("permission") == "run.services.setIamPolicy" and auth.get("granted") is True:
            return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get("resource", "resourceName", default="<RESOURCE_NOT_FOUND>")
    assigned_role = event.deep_walk("protoPayload", "response", "bindings", "role")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] was granted access to [{resource}] service with "
        f"the [{assigned_role}] role in project [{project_id}]"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    context["assigned_role"] = event.deep_walk(
        "protoPayload",
        "response",
        "bindings",
        "role",
    )
    return context
