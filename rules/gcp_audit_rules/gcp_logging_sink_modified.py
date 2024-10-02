import re

from gcp_base_helpers import gcp_alert_context


def rule(event):
    method_pattern = r"(?:\w+\.)*v\d\.(?:ConfigServiceV\d\.(?:UpdateSink))"
    match = re.search(method_pattern, event.deep_get("protoPayload", "methodName", default=""))
    return match is not None


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get(
        "protoPayload",
        "resourceName",
        default="<RESOURCE_NOT_FOUND>",
    )
    return f"[GCP]: [{actor}] updated logging sink [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
