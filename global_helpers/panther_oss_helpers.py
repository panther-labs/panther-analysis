"""Utility functions provided to policies and rules during execution."""

from datetime import datetime
from typing import Any, Dict, Optional, Sequence, Set, Union

import boto3
import panther_aws_helpers
import panther_base_helpers
import panther_ipinfo_helpers
from panther_detection_helpers import caching

# panther_oss_helpers.FIPS_ENABLED is DEPRECATED!!!  Instead use panther_aws_helpers.FIPS_ENABLED
FIPS_ENABLED = panther_aws_helpers.FIPS_ENABLED
# panther_oss_helpers.FIPS_SUFFIX is DEPRECATED!!!  Instead use panther_aws_helpers.FIPS_SUFFIX
FIPS_SUFFIX = panther_aws_helpers.FIPS_SUFFIX

# Auto Time Resolution Parameters
# panther_oss_helpers.EPOCH_REGEX is DEPRECATED!!!  Instead use panther_base_helpers.EPOCH_REGEX
EPOCH_REGEX = panther_base_helpers.EPOCH_REGEX
# panther_oss_helpers.TIME_FORMATS is DEPRECATED!!!  Instead use panther_base_helpers.TIME_FORMATS
TIME_FORMATS = panther_base_helpers.TIME_FORMATS


def resolve_timestamp_string(timestamp: str) -> Optional[datetime]:
    """Global `resolve_timestamp_string` is DEPRECATED.
    Instead, use `from panther_base_helpers import resolve_timestamp_string`."""
    return panther_base_helpers.resolve_timestamp_string(timestamp)


def get_s3_arn_by_name(name: str) -> str:
    """Global `get_s3_arn_by_name` is DEPRECATED.
    Instead, use `from panther_aws_helpers import get_s3_arn_by_name`."""
    return panther_aws_helpers.get_s3_arn_by_name(name)


def s3_lookup_by_name(name: str) -> Dict[str, Any]:
    """Global `s3_lookup_by_name` is DEPRECATED.
    Instead, use `from panther_aws_helpers import s3_lookup_by_name`."""
    return panther_aws_helpers.s3_lookup_by_name(name)


def resource_table() -> boto3.resource:
    """Global `resource_table` is DEPRECATED.
    Instead, use `from panther_aws_helpers import resource_table`."""
    return panther_aws_helpers.resource_table()


def resource_lookup(resource_id: str) -> Dict[str, Any]:
    """Global `resource_lookup` is DEPRECATED.
    Instead, use `from panther_aws_helpers import resource_lookup`."""
    return panther_aws_helpers.resource_lookup(resource_id)


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
    """Global `km_between_ipinfo_loc` is DEPRECATED.
    Instead, use `from panther_ipinfo_helpers.caching import km_between_ipinfo_loc`."""
    return panther_ipinfo_helpers.km_between_ipinfo_loc(ipinfo_loc_one, ipinfo_loc_two)


def geoinfo_from_ip(event, match_field: str):
    """Global `geoinfo_from_ip` is DEPRECATED.
    Instead, use `from panther_ipinfo_helpers.caching import geoinfo_from_ip`."""
    return panther_ipinfo_helpers.geoinfo_from_ip(event, match_field)


def geoinfo_from_ip_formatted(event, match_field: str) -> str:
    """Global `geoinfo_from_ip_formatted` is DEPRECATED.
    Instead, use `from panther_ipinfo_helpers.caching import geoinfo_from_ip_formatted`."""
    return panther_ipinfo_helpers.geoinfo_from_ip_formatted(event, match_field)


def time_delta(time1, time2: str) -> str:
    """Global `time_delta` is DEPRECATED.
    Instead, use `from panther_base_helpers import time_delta`."""
    return panther_base_helpers.time_delta(time1, time2)


def nano_to_micro(time_str: str) -> str:
    """Global `nano_to_micro` is DEPRECATED.
    Instead, use `from panther_base_helpers import nano_to_micro`."""
    return panther_base_helpers.nano_to_micro(time_str)


def add_parse_delay(event, context: dict) -> dict:
    """Global `add_parse_delay` is DEPRECATED.
    Instead, use `from panther_base_helpers import add_parse_delay`."""
    return panther_base_helpers.add_parse_delay(event, context)


def listify(maybe_list):
    """Global `listify` is DEPRECATED.
    Instead, use `from panther_base_helpers import listify`."""
    return panther_base_helpers.listify(maybe_list)
