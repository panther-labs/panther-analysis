import datetime as dt
import json

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_core import PantherEvent
from panther_detection_helpers.caching import get_string_set, put_string_set

# Determine how many secets must be accessed in order to trigger an alert
PARAM_THRESHOLD = 10

all_param_names = set()


def rule(event: PantherEvent) -> bool:
    # Exclude events of the wrong type
    if not (
        event.get("eventName") in ("GetParameter", "GetParameters")
        and event.deep_get("requestParameters", "withDecryption")
    ):
        return False

    # Determine if this actor accessed any other params in this account
    key = get_cache_key(event)
    cached_params = get_cached_param_names(key)
    accessed_params = get_param_names(event)

    # Determine if the cache needs updating with new entries
    global all_param_names  # pylint: disable=global-statement
    all_param_names = cached_params | accessed_params
    if all_param_names - cached_params:
        # Only set the TTL if this is the first time we're adding to the cache
        #   Otherwise we'll be perpetually extending the lifespan of the cached data every time we
        #   add more.
        put_string_set(key, all_param_names, epoch_seconds=(3600 if not cached_params else None))

    # Check combined number of params
    return len(all_param_names) > PARAM_THRESHOLD


def title(event: PantherEvent) -> str:
    actor = event.udm("actor_user")
    account_name = event.get("recipientAccountId")
    return f"Excessive SSM parameter decryption by [{actor}] in [{account_name}]"


def severity(event: PantherEvent) -> str:
    # Demote to LOW if attempt was denied
    if not aws_cloudtrail_success(event):
        return "LOW"
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    global all_param_names
    context = aws_rule_context(event)
    context.update({"accessedParams": list(all_param_names)})
    return context


def get_cache_key(event) -> str:
    """Use the field values in the event to generate a cache key unique to this actor and
    account ID."""
    offset = dt.datetime.fromisoformat(event["p_event_time"]).timestamp() // 3600 * 3600
    actor = event.udm("actor_user")
    account = event.get("recipientAccountId")
    rule_id = "AWS.SSM.DecryptSSMParams"
    return f"{rule_id}-{account}-{actor}-{offset}"


def get_param_names(event) -> set[str]:
    """Returns the accessed SSM Param names."""
    # Params could be either a list or a single entry
    params = set(event.deep_get("requestParameters", "names", default=[]))
    if single_param := event.deep_get("requestParameters", "name"):
        params.add(single_param)

    return params


def get_cached_param_names(key: str) -> set[str]:
    """Get any previously cached parameter names. Included automatic converstion from string in
    the case of a unit test mock."""
    cached_params = get_string_set(key, force_ttl_check=True)
    if isinstance(cached_params, str):
        # This is a unit test
        cached_params = set(json.loads(cached_params))
    return cached_params
