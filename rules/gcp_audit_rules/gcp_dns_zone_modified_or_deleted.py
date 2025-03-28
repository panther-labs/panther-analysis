from panther_gcp_helpers import gcp_alert_context


def rule(event):
    methods = (
        "dns.changes.create",
        "dns.managedZones.delete",
        "dns.managedZones.patch",
        "dns.managedZones.update",
    )
    return event.deep_get("protoPayload", "methodName", default="") in methods


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    return f"[GCP]: [{actor}] modified managed DNS zone [{resource}]"


def dedup(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return actor


def alert_context(event):
    return gcp_alert_context(event)
