import datetime as dt
import json

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_core import PantherEvent
from panther_detection_helpers.caching import get_string_set, put_string_set


def rule(event: PantherEvent) -> bool:
    if not (aws_cloudtrail_success(event) and event.get("eventName") == "SendSSHPublicKey"):
        return False

    offset = dt.datetime.fromisoformat(event["p_event_time"]).timestamp() // 3600 * 3600
    key = f"{event.deep_get('requestParameters', 'sSHPublicKey')}-{offset}"
    if not key:
        return False
    target_instance_id = event.deep_get("requestParameters", "instanceId")
    cached_instance_ids = get_cached_instance_ids(key)
    if len(cached_instance_ids) == 0:
        put_string_set(key, set(target_instance_id), epoch_seconds=3600)
        return False
    if target_instance_id not in cached_instance_ids:
        cached_instance_ids.add(target_instance_id)
        put_string_set(key, cached_instance_ids)
        return True
    return False


def title(event: PantherEvent) -> str:
    actor = event.udm("actor_user")
    account_name = event.get("recipientAccountId")
    return f"{actor} uploaded an SSH Key to multiple instances in {account_name}"


def dedup(event: PantherEvent) -> str:
    # Dedup based on the public SSH key
    return event.deep_get("requestParameters", "sSHPublicKey")


def alert_context(event: PantherEvent) -> dict:
    context = aws_rule_context(event)
    context["instanceId"] = event.deep_get(
        "requestParameters", "instanceId", default="<UNKNOWN EC2 INSTANCE ID>"
    )
    return context


def get_cached_instance_ids(key: str) -> set[str]:
    """Get any previously cached parameter names. Included automatic converstion from string in
    the case of a unit test mock."""
    cached_ids = get_string_set(key, force_ttl_check=True)
    if isinstance(cached_ids, str):
        # This is a unit test
        cached_ids = set(json.loads(cached_ids))
    return cached_ids
