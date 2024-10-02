from gcp_base_helpers import gcp_alert_context


def rule(event):
    reason = event.deep_walk("protoPayload", "status", "details", "reason", default="")
    return reason == "IAM_PERMISSION_DENIED"


def title(event):
    actor = event.deep_walk(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return f"[GCP]: [{actor}] performed multiple requests resulting in [IAM_PERMISSION_DENIED]"


def alert_context(event):
    return gcp_alert_context(event)
