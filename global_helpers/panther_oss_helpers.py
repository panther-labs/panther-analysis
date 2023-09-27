"""Utility functions provided to policies and rules during execution."""
import json
import os
import re
from datetime import datetime
from ipaddress import ip_address
from math import atan2, cos, radians, sin, sqrt
from typing import Any, Dict, Optional, Sequence, Set, Union

import boto3
import requests
from dateutil import parser
from panther_detection_helpers import caching

_RESOURCE_TABLE = None  # boto3.Table resource, lazily constructed
FIPS_ENABLED = os.getenv("ENABLE_FIPS", "").lower() == "true"
FIPS_SUFFIX = "-fips." + os.getenv("AWS_REGION", "") + ".amazonaws.com"

# Auto Time Resolution Parameters
EPOCH_REGEX = r"([0-9]{9,12}(\.\d+)?)"
TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",  # Panther p_event_time Timestamp
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
    except (ValueError, TypeError, parser.ParserError):
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
            "dynamodb",
            endpoint_url="https://dynamodb" + FIPS_SUFFIX if FIPS_ENABLED else None,
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


def ttl_expired(response: dict) -> bool:
    """Global `ttl_expired` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import ttl_expired`."""
    return caching.ttl_expired(response)


def get_counter(key: str, force_ttl_check: bool = False) -> int:
    """Global `get_counter` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import get_counter`."""
    return caching.get_counter(key=key, force_ttl_check=force_ttl_check)


def increment_counter(key: str, val: int = 1) -> int:
    """Global `increment_counter` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import increment_counter`."""
    return caching.increment_counter(key=key, val=val)


def reset_counter(key: str) -> None:
    """Global `reset_counter` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import reset_counter`."""
    return caching.reset_counter(key=key)


def set_key_expiration(key: str, epoch_seconds: int) -> None:
    """Global `set_key_expiration` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import set_key_expiration`."""
    return caching.set_key_expiration(key=key, epoch_seconds=epoch_seconds)


def put_dictionary(key: str, val: dict, epoch_seconds: int = None):
    """Global `put_dictionary` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import put_dictionary`."""
    return caching.put_dictionary(key=key, val=val, epoch_seconds=epoch_seconds)


def get_dictionary(key: str, force_ttl_check: bool = False) -> dict:
    """Global `get_dictionary` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import get_dictionary`."""
    return caching.get_dictionary(key=key, force_ttl_check=force_ttl_check)


def get_string_set(key: str, force_ttl_check: bool = False) -> Set[str]:
    """Global `get_string_set` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import get_string_set`."""
    return caching.get_string_set(key=key, force_ttl_check=force_ttl_check)


def put_string_set(key: str, val: Sequence[str], epoch_seconds: int = None) -> None:
    """Global `put_string_set` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import put_string_set`."""
    return caching.put_string_set(key=key, val=val, epoch_seconds=epoch_seconds)


def add_to_string_set(key: str, val: Union[str, Sequence[str]]) -> Set[str]:
    """Global `add_to_string_set` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import add_to_string_set`."""
    return caching.add_to_string_set(key=key, val=val)


def remove_from_string_set(key: str, val: Union[str, Sequence[str]]) -> Set[str]:
    """Global `remove_from_string_set` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import remove_from_string_set`."""
    return caching.remove_from_string_set(key=key, val=val)


def reset_string_set(key: str) -> None:
    """Global `reset_string_set` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import reset_string_set`."""
    return caching.reset_string_set(key=key)


def evaluate_threshold(key: str, threshold: int = 10, expiry_seconds: int = 3600) -> bool:
    """Global `evaluate_threshold` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import evaluate_threshold`."""
    return caching.evaluate_threshold(key=key, threshold=threshold, expiry_seconds=expiry_seconds)


def check_account_age(key):
    """Global `check_account_age` is DEPRECATED.
    Instead, use `from panther_detection_helpers.caching import check_account_age`."""
    return caching.check_account_age(key=key)


def km_between_ipinfo_loc(ipinfo_loc_one: dict, ipinfo_loc_two: dict):
    """
    compute the number of kilometers between two ipinfo_location enrichments
    This uses a haversine computation which is imperfect and holds the benefit
    of being supportable via stdlib. At polar opposites, haversine might be
    0.3-0.5% off
    See also https://en.wikipedia.org/wiki/Haversine_formula
    See also https://stackoverflow.com/a/19412565
    See also https://www.sunearthtools.com/tools/distance.php
    """
    if not set({"lat", "lng"}).issubset(set(ipinfo_loc_one.keys())):
        # input ipinfo_loc_one doesn't have lat and lng keys
        return None
    if not set({"lat", "lng"}).issubset(set(ipinfo_loc_two.keys())):
        # input ipinfo_loc_two doesn't have lat and lng keys
        return None
    lat_1 = radians(float(ipinfo_loc_one.get("lat")))
    lng_1 = radians(float(ipinfo_loc_one.get("lng")))
    lat_2 = radians(float(ipinfo_loc_two.get("lat")))
    lng_2 = radians(float(ipinfo_loc_two.get("lng")))
    # radius of the earth in kms
    radius = 6372.795477598
    lng_diff = lng_2 - lng_1
    lat_diff = lat_2 - lat_1

    step_1 = sin(lat_diff / 2) ** 2 + cos(lat_1) * cos(lat_2) * sin(lng_diff / 2) ** 2
    step_2 = 2 * atan2(sqrt(step_1), sqrt(1 - step_1))
    distance = radius * step_2
    return distance


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
    resp = requests.get(url, timeout=5)
    if resp.status_code != 200:
        raise Exception(f"Geo lookup failed: GET {url} returned {resp.status_code}")
    geoinfo = json.loads(resp.text)
    return geoinfo


def geoinfo_from_ip_formatted(ip: str) -> str:  # pylint: disable=invalid-name
    """Formatting wrapper for geoinfo_from_ip for use in human-readable text"""
    geoinfo = geoinfo_from_ip(ip)
    return (
        f"{geoinfo.get('ip')} in {geoinfo.get('city')}, "
        f"{geoinfo.get('region')} in {geoinfo.get('country')}"
    )


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
    # pylint: disable=consider-using-f-string
    parts[-1] = "{:06f}".format(float(parts[-1]))
    return ":".join(parts)


# adds parsing delay to an alert_context
def add_parse_delay(event, context: dict) -> dict:
    parsing_delay = time_delta(event.get("p_event_time"), event.get("p_parse_time"))
    context["parseDelay"] = f"{parsing_delay}"
    return context


# When a single item is loaded from json, it is loaded as a single item
# When a list of items is loaded from json, it is loaded as a list of that item
# When we want to iterate over something that could be a single item or a list
# of items we can use listify and just continue as if it's always a list
def listify(maybe_list):
    try:
        iter(maybe_list)
    except TypeError:
        # not a list
        return [maybe_list]
    # either a list or string
    return [maybe_list] if isinstance(maybe_list, (str, bytes, dict)) else maybe_list
