"""Utility functions provided to policies and rules during execution."""
import json
import os
import re
import time
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, Optional, Sequence, Set, Union
from dateutil import parser

import boto3
import requests

_RESOURCE_TABLE = None  # boto3.Table resource, lazily constructed
FIPS_ENABLED = os.getenv("ENABLE_FIPS", "").lower() == "true"
FIPS_SUFFIX = "-fips." + os.getenv("AWS_REGION", "") + ".amazonaws.com"

# Auto Time Resolution Parameters
EPOCH_REGEX = r"([0-9]{9,12}(\.\d+)?)"
TIME_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",  # AWS Timestamp
    "%Y-%m-%dT%H:%M:%S.%fZ",  # Panther Timestamp
    "%Y-%m-%dT%H:%M:%S*%f%z",
    "%Y %b %d %H:%M:%S.%f %Z",
    "%b %d %H:%M:%S %z %Y",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d, %Y %I:%M:%S %p",
    "%b %d %Y %H:%M:%S",
    "%b %d %H:%M:%S %Y",
    "%b %d %H:%M:%S %z",
    "%b %d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y/%m/%d*%H:%M:%S",
    "%Y %b %d %H:%M:%S.%f*%Z",
    "%Y %b %d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d*%H:%M:%S:%f",
    "%Y-%m-%d*%H:%M:%S",
    "%y-%m-%d %H:%M:%S,%f %z",
    "%y-%m-%d %H:%M:%S,%f",
    "%y-%m-%d %H:%M:%S",
    "%y/%m/%d %H:%M:%S",
    "%y%m%d %H:%M:%S",
    "%Y%m%d %H:%M:%S.%f",
    "%m/%d/%y*%H:%M:%S",
    "%m/%d/%Y*%H:%M:%S",
    "%m/%d/%Y*%H:%M:%S*%f",
    "%m/%d/%y %H:%M:%S %z",
    "%m/%d/%Y %H:%M:%S %z",
    "%H:%M:%S",
    "%H:%M:%S.%f",
    "%H:%M:%S,%f",
    "%d/%b %H:%M:%S,%f",
    "%d/%b/%Y:%H:%M:%S",
    "%d/%b/%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S.%f",
    "%d %b %Y %H:%M:%S",
    "%d %b %Y %H:%M:%S*%f",
    "%m%d_%H:%M:%S",
    "%m%d_%H:%M:%S.%f",
    "%m/%d/%Y %I:%M:%S %p:%f",
    "%m/%d/%Y %I:%M:%S %p",
]


class BadLookup(Exception):
    """Error returned when a resource lookup fails."""


class PantherBadInput(Exception):
    """Error returned when a Panther helper function is provided bad input."""


def resolve_timestamp_string(timestamp: str) -> Optional[datetime]:
    """Auto Time Resolution"""
    if not timestamp:
        return None

    # Removes weird single-quotes used in some timestamp formats
    ts_format = timestamp.replace("'", "")
    # Attempt to resolve timestamp format
    for each_format in TIME_FORMATS:
        try:
            return datetime.strptime(ts_format, each_format)
        except (ValueError, TypeError):
            continue
    try:
        return parser.parse(timestamp)
    except(ValueError, TypeError, parser.ParserError):
        pass

    # Attempt to resolve epoch format
    # Since datetime.utcfromtimestamp supports 9 through 12 digit epoch timestamps
    # and we only want the first 12 digits.
    match = re.match(EPOCH_REGEX, timestamp)
    if match.group(0) != "":
        try:
            return datetime.utcfromtimestamp(float(match.group(0)))
        except (ValueError, TypeError):
            return None
    return None


def get_s3_arn_by_name(name: str) -> str:
    """This function is used to construct an s3 bucket ARN from its name."""
    if name == "":
        raise PantherBadInput("s3 name cannot be blank")
    return "arn:aws:s3:::" + name


def s3_lookup_by_name(name: str) -> Dict[str, Any]:
    """This function is used to get an S3 bucket resource from just its name."""
    return resource_lookup(get_s3_arn_by_name(name))


def resource_table() -> boto3.resource:
    """Lazily build resource table"""
    # pylint: disable=global-statement
    global _RESOURCE_TABLE
    if not _RESOURCE_TABLE:
        # pylint: disable=no-member
        _RESOURCE_TABLE = boto3.resource(
            "dynamodb", endpoint_url="https://dynamodb" + FIPS_SUFFIX if FIPS_ENABLED else None
        ).Table("panther-resources")
    return _RESOURCE_TABLE


def resource_lookup(resource_id: str) -> Dict[str, Any]:
    """This function is used to get a resource from the resources-api based on its resourceID."""
    # Validate input so we can provide meaningful error messages to users
    if resource_id == "":
        raise PantherBadInput("resourceId cannot be blank")

    # Get the item from dynamo
    response = resource_table().get_item(Key={"id": resource_id})

    # Check if dynamo failed
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        raise BadLookup("dynamodb - " + str(status_code) + " HTTPStatusCode")

    # Check if the item was found
    if "Item" not in response:
        raise BadLookup(resource_id + " not found")

    # Return just the attributes of the item
    return response["Item"]["attributes"]


# Helper functions for accessing Dynamo key-value store.
#
# Keys can be any string specified by rules and policies,
# values are integer counters and/or string sets.
#
# Use kv_table() if you want to interact with the table directly.
_KV_TABLE = None
_COUNT_COL = "intCount"
_STRING_SET_COL = "stringSet"


def kv_table() -> boto3.resource:
    """Lazily build key-value table resource"""
    # pylint: disable=global-statement
    global _KV_TABLE
    if not _KV_TABLE:
        # pylint: disable=no-member
        _KV_TABLE = boto3.resource(
            "dynamodb", endpoint_url="https://dynamodb" + FIPS_SUFFIX if FIPS_ENABLED else None
        ).Table("panther-kv-store")
    return _KV_TABLE


def get_counter(key: str) -> int:
    """Get a counter's current value (defaulting to 0 if key does not exist)."""
    response = kv_table().get_item(
        Key={"key": key},
        ProjectionExpression=_COUNT_COL,
    )
    return response.get("Item", {}).get(_COUNT_COL, 0)


def increment_counter(key: str, val: int = 1) -> int:
    """Increment a counter in the table.

    Args:
        key: The name of the counter (need not exist yet)
        val: How much to add to the counter

    Returns:
        The new value of the count
    """
    response = kv_table().update_item(
        Key={"key": key},
        ReturnValues="UPDATED_NEW",
        UpdateExpression="ADD #col :incr",
        ExpressionAttributeNames={"#col": _COUNT_COL},
        ExpressionAttributeValues={":incr": val},
    )

    # Numeric values are returned as decimal.Decimal
    return response["Attributes"][_COUNT_COL].to_integral_value()


def reset_counter(key: str) -> None:
    """Reset a counter to 0."""
    kv_table().put_item(Item={"key": key, _COUNT_COL: 0})


def set_key_expiration(key: str, epoch_seconds: int) -> None:
    """Configure the key to automatically expire at the given time.

    DynamoDB typically deletes expired items within 48 hours of expiration.

    Args:
        key: The name of the counter
        epoch_seconds: When you want the counter to expire (set to 0 to disable)
    """
    kv_table().update_item(
        Key={"key": key},
        UpdateExpression="SET expiresAt = :time",
        ExpressionAttributeValues={":time": epoch_seconds},
    )


def get_string_set(key: str) -> Set[str]:
    """Get a string set's current value (defaulting to empty set if key does not exit)."""
    response = kv_table().get_item(
        Key={"key": key},
        ProjectionExpression=_STRING_SET_COL,
    )
    return response.get("Item", {}).get(_STRING_SET_COL, set())


def put_string_set(key: str, val: Sequence[str]) -> None:
    """Overwrite a string set under the given key.

    This is faster than (reset_string_set + add_string_set) if you know exactly what the contents
    of the set should be.

    Args:
        key: The name of the string set
        val: A list/set/tuple of strings to store
    """
    if not val:
        # Can't put an empty string set - remove it instead
        reset_string_set(key)
    else:
        kv_table().put_item(Item={"key": key, _STRING_SET_COL: set(val)})


def add_to_string_set(key: str, val: Union[str, Sequence[str]]) -> Set[str]:
    """Add one or more strings to a set.

    Args:
        key: The name of the string set
        val: Either a single string or a list/tuple/set of strings to add

    Returns:
        The new value of the string set
    """
    if isinstance(val, str):
        item_value = {val}
    else:
        item_value = set(val)
        if not item_value:
            # We can't add empty sets, just return the existing value instead
            return get_string_set(key)

    response = kv_table().update_item(
        Key={"key": key},
        ReturnValues="UPDATED_NEW",
        UpdateExpression="ADD #col :ss",
        ExpressionAttributeNames={"#col": _STRING_SET_COL},
        ExpressionAttributeValues={":ss": item_value},
    )
    return response["Attributes"][_STRING_SET_COL]


def remove_from_string_set(key: str, val: Union[str, Sequence[str]]) -> Set[str]:
    """Remove one or more strings from a set.

    Args:
        key: The name of the string set
        val: Either a single string or a list/tuple/set of strings to remove

    Returns:
        The new value of the string set
    """
    if isinstance(val, str):
        item_value = {val}
    else:
        item_value = set(val)
        if not item_value:
            # We can't remove empty sets, just return the existing value instead
            return get_string_set(key)

    response = kv_table().update_item(
        Key={"key": key},
        ReturnValues="UPDATED_NEW",
        UpdateExpression="DELETE #col :ss",
        ExpressionAttributeNames={"#col": _STRING_SET_COL},
        ExpressionAttributeValues={":ss": item_value},
    )
    return response["Attributes"][_STRING_SET_COL]


def reset_string_set(key: str) -> None:
    """Reset a string set to empty."""
    kv_table().update_item(
        Key={"key": key},
        UpdateExpression="REMOVE #col",
        ExpressionAttributeNames={"#col": _STRING_SET_COL},
    )


def evaluate_threshold(key: str, threshold: int = 10, expiry_seconds: int = 3600) -> bool:
    hourly_error_count = increment_counter(key)
    if hourly_error_count == 1:
        set_key_expiration(key, int(time.time()) + expiry_seconds)
    # If it exceeds our threshold, reset and then return an alert
    elif hourly_error_count >= threshold:
        reset_counter(key)
        return True
    return False


def geoinfo_from_ip(ip: str) -> dict:  # pylint: disable=invalid-name
    """Looks up the geolocation of an IP address using ipinfo.io

    Example ipinfo output:
    {
      "ip": "1.1.1.1",
      "hostname": "one.one.one.one",
      "anycast": true,
      "city": "Miami",
      "region": "Florida",
      "country": "US",
      "loc": "25.7867,-80.1800",
      "org": "AS13335 Cloudflare, Inc.",
      "postal": "33132",
      "timezone": "America/New_York",
      "readme": "https://ipinfo.io/missingauth"
    }
    """

    valid_ip = ip_address(ip)
    url = f"https://ipinfo.io/{valid_ip}/json"
    resp = requests.get(url)
    if resp.status_code != 200:
        raise Exception(f"Geo lookup failed: GET {url} returned {resp.status_code}")
    geoinfo = json.loads(resp.text)
    return geoinfo


def geoinfo_from_ip_formatted(ip: str) -> str:  # pylint: disable=invalid-name
    """Formatting wrapper for geoinfo_from_ip for use in human-readable text"""
    geoinfo = geoinfo_from_ip(ip)
    geoinfo_string = (
        f"{geoinfo.get('ip')} in {geoinfo.get('city')}, "
        f"{geoinfo.get('region')} in {geoinfo.get('country')}"
    )
    return geoinfo_string


# returns the difference between time1 and later time 2 in human-readable time period string
def time_delta(time1, time2: str) -> str:
    time1_truncated = nano_to_micro(time1)
    time2_truncated = nano_to_micro(time2)
    delta_timedelta = resolve_timestamp_string(time2_truncated) - resolve_timestamp_string(
        time1_truncated
    )
    days = delta_timedelta.days
    hours, remainder = divmod(delta_timedelta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    delta = ""
    if days > 0:
        delta = f"{days} day(s) "
    if hours > 0:
        delta = "".join([delta, f"{hours} hour(s) "])
    if minutes > 0:
        delta = "".join([delta, f"{minutes} minute(s) "])
    if seconds > 0:
        delta = "".join([delta, f"{seconds} second(s)"])
    return delta


def nano_to_micro(time_str: str) -> str:
    parts = time_str.split(":")
    parts[-1] = "{:06f}".format(float(parts[-1]))
    return ":".join(parts)


# adds parsing delay to an alert_context
def add_parse_delay(event, context: dict) -> dict:
    parsing_delay = time_delta(event.get("p_event_time"), event.get("p_parse_time"))
    context["parseDelay"] = f"{parsing_delay}"
    return context

# check for presence of user id in KV store for the purpose of modifying severity or suppressing
# alerts based on expected actions for a new user
def check_new_user(user_id):
    return bool(get_string_set(user_id))


def _test_kv_store():
    """Integration tests which validate the functions which interact with the key-value store.

    Deploy Panther and then simply run "python3 panther.py" to test.
    """
    assert increment_counter("panther", 1) == 1
    assert increment_counter("labs", 3) == 3
    assert increment_counter("panther", -2) == -1
    assert increment_counter("panther", 0) == -1
    assert increment_counter("panther", 11) == 10

    assert get_counter("panther") == 10
    assert get_counter("labs") == 3
    assert get_counter("nonexistent") == 0

    reset_counter("panther")
    reset_counter("labs")
    assert get_counter("panther") == 0
    assert get_counter("labs") == 0

    set_key_expiration("panther", int(time.time()))

    # Add elements in a list, tuple, set, or as singleton strings
    # The same key can be used to store int counts and string sets
    assert add_to_string_set("panther", ["a", "b"]) == {"a", "b"}
    assert add_to_string_set("panther", ["b", "a"]) == {"a", "b"}
    assert add_to_string_set("panther", "c") == {"a", "b", "c"}
    assert add_to_string_set("panther", set()) == {"a", "b", "c"}
    assert add_to_string_set("panther", {"b", "c", "d"}) == {"a", "b", "c", "d"}
    assert add_to_string_set("panther", ("d", "e")) == {"a", "b", "c", "d", "e"}

    # Empty strings are allowed
    assert add_to_string_set("panther", "") == {"a", "b", "c", "d", "e", ""}

    assert get_string_set("labs") == set()
    assert get_string_set("panther") == {"a", "b", "c", "d", "e", ""}

    assert remove_from_string_set("panther", ["b", "c", "d"]) == {"a", "e", ""}
    assert remove_from_string_set("panther", "") == {"a", "e"}
    assert remove_from_string_set("panther", "") == {"a", "e"}

    # Overwrite contents completely
    put_string_set("panther", ["go", "python"])
    assert get_string_set("panther") == {"go", "python"}
    put_string_set("labs", [])
    assert get_string_set("labs") == set()

    reset_string_set("panther")
    reset_string_set("nonexistent")  # no error
    assert get_string_set("panther") == set()


if __name__ == "__main__":
    _test_kv_store()
