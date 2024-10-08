import re

from panther_gcp_helpers import gcp_alert_context


def rule(event):
    method_pattern = r"(?:\w+\.)*v\d\.(?:Firewall\.Update)|(compute\.firewalls\.(patch|update))"
    match = re.search(method_pattern, event.deep_get("protoPayload", "methodName", default=""))
    return match is not None


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    return f"[GCP]: [{actor}] modified firewall rule on [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
