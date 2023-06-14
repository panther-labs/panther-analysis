from typing import Any, List

from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get


def _get_details(event) -> List[Any]:
    return deep_get(event, "protoPayload", "status", "details", default=[{}])


def rule(event):
    details = _get_details(event)
    if len(details) > 0:
        reason = deep_get(details[0], "reason", default="")
        if reason == "IAM_PERMISSION_DENIED":
            return True
    return False


def title(event):
    details = _get_details(event)
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    permission = "<PERMISSION_NOT_FOUND>"
    if len(details) > 0:
        permission = deep_get(
            details[0], "metadata", "permission", default="<PERMISSION_NOT_FOUND>"
        )
    return (
        f"[GCP]: [{actor}] performed multiple [{permission}] requests "
        "resulting in [IAM_PERMISSION_DENIED]"
    )


def alert_context(event):
    return gcp_alert_context(event)
