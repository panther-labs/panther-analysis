from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if not event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND").endswith(
        "CloudBuild.CreateBuild"
    ):
        return False

    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    # Get the principal (actor) email
    principal = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="")

    # Skip whitelisted service accounts
    if principal.endswith("@gcf-admin-robot.iam.gserviceaccount.com"):
        return False

    # Check if build.create permission was granted
    for auth in authorization_info:
        if auth.get("permission") == "cloudbuild.builds.create" and auth.get("granted") is True:
            return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"


def alert_context(event):
    return gcp_alert_context(event)
