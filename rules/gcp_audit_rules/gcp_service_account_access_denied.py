from typing import Any, List

from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get


def rule(event):
    reason = next(
        (
            deep_get(item, "reason", default="")
            for item in deep_get(event, "protoPayload", "status", "details", default=[{}])
            if len(item) > 0
        ),
        "",
    )
    return reason == "IAM_PERMISSION_DENIED"


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return f"[GCP]: [{actor}] performed multiple requests resulting in [IAM_PERMISSION_DENIED]"


def alert_context(event):
    return gcp_alert_context(event)
