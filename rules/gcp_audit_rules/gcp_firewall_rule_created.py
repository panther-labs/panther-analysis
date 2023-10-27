import re

from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get


def rule(event):
    method_pattern = r"(?:\w+\.)*v\d\.(?:Firewall\.Create)|(compute\.firewalls\.insert)"
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
    resource_id = deep_get(
        event,
        "resource",
        "labels",
        "firewall_rule_id",
        default="<RESOURCE_ID_NOT_FOUND>",
    )
    if resource_id != "<RESOURCE_ID_NOT_FOUND>":
        return f"[GCP]: [{actor}] created firewall rule with resource ID [{resource_id}]"
    return f"[GCP]: [{actor}] created firewall rule for resource [{resource}]"


def alert_context(event):
    return gcp_alert_context(event)
