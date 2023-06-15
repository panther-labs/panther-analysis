import re

from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get


def rule(event):
    method_pattern = r"(?:\w+\.)*v\d\.(?:ConfigServiceV\d\.(?:UpdateSink))"
    match = re.search(method_pattern, deep_get(event, "protoPayload", "methodName", default=""))
    return match is not None


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = deep_get(
        event,
        "protoPayload",
        "resourceName",
        default="<RESOURCE_NOT_FOUND>",
    )
    return f"[GCP]: [{actor}] updated logging sink [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
