from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get


def rule(event):
    methods = (
        "dns.changes.create",
        "dns.managedZones.delete",
        "dns.managedZones.patch",
        "dns.managedZones.update",
    )
    return deep_get(event, "protoPayload", "methodName", default="") in methods


def title(event):
    actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="")
    method = deep_get(event, "protoPayload", "methodName", default="")
    resource = deep_get(event, "protoPayload", "resourceName", default="")
    return f"[GCP] {actor} performed {method} on {resource}"


def alert_context(event):
    return gcp_alert_context(event)
