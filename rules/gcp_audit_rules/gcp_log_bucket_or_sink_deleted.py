import re

from panther_gcp_helpers import gcp_alert_context


def rule(event):
    granted_list = event.deep_walk("protoPayload", "authorizationInfo", "granted", default=[])
    authenticated = any(granted_list) if isinstance(granted_list, list) else bool(granted_list)
    method_pattern = r"(?:\w+\.)*v\d\.(?:ConfigServiceV\d\.(?:Delete(Bucket|Sink)))"
    match = re.search(method_pattern, event.deep_get("protoPayload", "methodName", default=""))
    return authenticated and match is not None


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get(
        "protoPayload",
        "resourceName",
        default="<RESOURCE_NOT_FOUND>",
    )
    return f"[GCP]: [{actor}] deleted logging bucket or sink [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
