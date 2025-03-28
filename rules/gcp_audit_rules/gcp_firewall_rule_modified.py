import re

from panther_gcp_helpers import gcp_alert_context


RULE_MODIFIED_PARTS = [
    ".Firewall.Update",
    ".compute.firewalls.patch",
    ".compute.firewalls.update",
]

def rule(event):
    method = event.deep_get("protoPayload", "methodName", default="")
    return any(part in method for part in RULE_MODIFIED_PARTS)


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    return f"[GCP]: [{actor}] modified firewall rule on [{resource}]"


def dedup(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return actor


def alert_context(event):
    return gcp_alert_context(event)
