import datetime as dt
import json

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_core import PantherEvent
from panther_detection_helpers.caching import get_string_set, put_string_set

# Determine how separate instances need be commanded in order to trigger an alert
INSTANCE_THRESHOLD = 2

all_instance_ids = set()


def rule(event: PantherEvent) -> bool:
    # Exclude events of the wrong type
    if event.get("eventName") != "SendCommand":
        return False

    # Determine if this actor accessed any other params in this account
    key = get_cache_key(event)
    cached_ids = get_cached_instance_ids(key)
    target_instance_ids = set(event.deep_get("requestParameters", "instanceIds", default=[]))

    # Determine if the cache needs updating with new entries
    global all_instance_ids  # pylint: disable=global-statement
    all_instance_ids = cached_ids | target_instance_ids
    if all_instance_ids - cached_ids:
        # Only set the TTL if this is the first time we're adding to the cache
        #   Otherwise we'll be perpetually extending the lifespan of the cached data every time we
        #   add more.
        put_string_set(key, all_instance_ids, epoch_seconds=(3600 if not cached_ids else None))

    # Check combined number of params
    return len(all_instance_ids) > INSTANCE_THRESHOLD


def title(event: PantherEvent) -> str:
    actor = event.udm("actor_user")
    account_name = event.get("recipientAccountId")
    return f"Commands distributed to many EC2 instances by [{actor}] in [{account_name}]"


def severity(event: PantherEvent) -> str:
    # Demote to LOW if attempt was denied
    if not aws_cloudtrail_success(event):
        return "LOW"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    global all_instance_ids
    context = aws_rule_context(event)
    context.update({"instanceIds": list(all_instance_ids)})
    return context


def get_cache_key(event) -> str:
    """Use the field values in the event to generate a cache key unique to this actor and
    account ID."""
    offset = dt.datetime.fromisoformat(event["p_event_time"]).timestamp() // 3600 * 3600
    actor = event.udm("actor_user")
    account = event.get("recipientAccountId")
    rule_id = "AWS.SSM.DistributedCommand"
    return f"{rule_id}-{account}-{actor}-{offset}"


def get_cached_instance_ids(key: str) -> set[str]:
    """Get any previously cached parameter names. Included automatic converstion from string in
    the case of a unit test mock."""
    cached_ids = get_string_set(key, force_ttl_check=True)
    if isinstance(cached_ids, str):
        # This is a unit test
        cached_ids = set(json.loads(cached_ids))
    return cached_ids
