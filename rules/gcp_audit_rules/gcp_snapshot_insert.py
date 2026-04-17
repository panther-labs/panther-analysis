from panther_gcp_helpers import gcp_alert_context

EXPECTED_DOMAIN = "@your-domain.tld"


def rule(event):
    if event.deep_get("protoPayload", "response", "error"):
        return False

    method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if method != "v1.compute.snapshots.insert":
        return False

    email = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="")
    if not email.endswith(EXPECTED_DOMAIN):
        return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
    return f"[GCP]: Unexpected domain [{actor}] created a snapshot on project [{project}]"


def alert_context(event):
    return gcp_alert_context(event)
