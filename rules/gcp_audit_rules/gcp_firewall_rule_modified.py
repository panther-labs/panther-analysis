import re

from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get


def rule(event):
    method_pattern = r"(?:\w+\.)*v1\.(?:Firewall\.Update)|(compute\.firewalls\.(patch|update))"
    match = re.search(method_pattern, deep_get(event, "protoPayload", "methodName", default=""))
    return match is not None


def title(event):
    actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="")
    method = deep_get(event, "protoPayload", "methodName", default="")
    resource = deep_get(event, "protoPayload", "resourceName", default="")
    return f"[GCP] {actor} performed {method} on {resource}"


def alert_context(event):
    return gcp_alert_context(event)
