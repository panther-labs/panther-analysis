from panther_gcp_helpers import gcp_alert_context

RULE_CREATED_PARTS = [
    ".Firewall.Create",
    ".compute.firewalls.insert",
]


def rule(event):
    method = event.deep_get("protoPayload", "methodName", default="")
    return any(part in method for part in RULE_CREATED_PARTS)


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get(
        "protoPayload",
        "resourceName",
        default="<RESOURCE_NOT_FOUND>",
    )
    resource_id = event.deep_get(
        "resource",
        "labels",
        "firewall_rule_id",
        default="<RESOURCE_ID_NOT_FOUND>",
    )
    if resource_id != "<RESOURCE_ID_NOT_FOUND>":
        return f"[GCP]: [{actor}] created firewall rule with resource ID [{resource_id}]"
    return f"[GCP]: [{actor}] created firewall rule for resource [{resource}]"


def dedup(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return actor


def alert_context(event):
    return gcp_alert_context(event)
