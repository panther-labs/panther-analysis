"""Utility functions provided to policies and rules during execution."""
from fnmatch import fnmatch
from ipaddress import ip_network
import time
from typing import Any, Dict, Union, Sequence, Set

import boto3

_RESOURCE_TABLE = None  # boto3.Table resource, lazily constructed


class BadLookup(Exception):
    """Error returned when a resource lookup fails."""


class PantherBadInput(Exception):
    """Error returned when a Panther helper function is provided bad input."""


def get_s3_arn_by_name(name: str) -> str:
    """This function is used to construct an s3 bucket ARN from its name."""
    if name == '':
        raise PantherBadInput('s3 name cannot be blank')
    return 'arn:aws:s3:::' + name


def s3_lookup_by_name(name: str) -> Dict[str, Any]:
    """This function is used to get an S3 bucket resource from just its name."""
    return resource_lookup(get_s3_arn_by_name(name))


def resource_table() -> boto3.resource:
    """Lazily build resource table"""
    # pylint: disable=global-statement
    global _RESOURCE_TABLE
    if not _RESOURCE_TABLE:
        # pylint: disable=no-member
        _RESOURCE_TABLE = boto3.resource('dynamodb').Table('panther-resources')
    return _RESOURCE_TABLE


def resource_lookup(resource_id: str) -> Dict[str, Any]:
    """This function is used to get a resource from the resources-api based on its resourceID."""
    # Validate input so we can provide meaningful error messages to users
    if resource_id == '':
        raise PantherBadInput('resourceId cannot be blank')

    # Get the item from dynamo
    response = resource_table().get_item(Key={'id': resource_id})

    # Check if dynamo failed
    status_code = response['ResponseMetadata']['HTTPStatusCode']
    if status_code != 200:
        raise BadLookup('dynamodb - ' + str(status_code) + ' HTTPStatusCode')

    # Check if the item was found
    if 'Item' not in response:
        raise BadLookup(resource_id + ' not found')

    # Return just the attributes of the item
    return response['Item']['attributes']


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as DMZ space.
DMZ_NETWORKS = [
    ip_network('10.1.0.0/24'),
    ip_network('100.1.0.0/24'),
]


def is_dmz_cidr(ip_range):
    """This function determines whether a given IP range is within the defined DMZ IP range."""
    return any(
        ip_network(ip_range).overlaps(dmz_network)
        for dmz_network in DMZ_NETWORKS)


DMZ_TAG_KEY = 'environment'
DMZ_TAG_VALUE = 'dmz'


# Defaults to False to assume something is not a DMZ if it is not tagged
def is_dmz_tags(resource):
    """This function determines whether a given resource is tagged as exisitng in a DMZ."""
    if resource['Tags'] is None:
        return False
    return resource['Tags'].get(DMZ_TAG_KEY) == DMZ_TAG_VALUE


# Helper functions for accessing Dynamo key-value store.
#
# Keys can be any string specified by rules and policies,
# values are integer counters and/or string sets.
#
# Use kv_table() if you want to interact with the table directly.
_KV_TABLE = None
_COUNT_COL = 'intCount'
_STRING_SET_COL = 'stringSet'


def kv_table() -> boto3.resource:
    """Lazily build key-value table resource"""
    # pylint: disable=global-statement
    global _KV_TABLE
    if not _KV_TABLE:
        # pylint: disable=no-member
        _KV_TABLE = boto3.resource('dynamodb').Table('panther-kv-store')
    return _KV_TABLE


def get_counter(key: str) -> int:
    """Get a counter's current value (defaulting to 0 if key does not exist)."""
    response = kv_table().get_item(
        Key={'key': key},
        ProjectionExpression=_COUNT_COL,
    )
    return response.get('Item', {}).get(_COUNT_COL, 0)


def increment_counter(key: str, val: int = 1) -> int:
    """Increment a counter in the table.

    Args:
        key: The name of the counter (need not exist yet)
        val: How much to add to the counter

    Returns:
        The new value of the count
    """
    response = kv_table().update_item(
        Key={'key': key},
        ReturnValues='UPDATED_NEW',
        UpdateExpression='ADD #col :incr',
        ExpressionAttributeNames={'#col': _COUNT_COL},
        ExpressionAttributeValues={':incr': val},
    )

    # Numeric values are returned as decimal.Decimal
    return response['Attributes'][_COUNT_COL].to_integral_value()


def reset_counter(key: str) -> None:
    """Reset a counter to 0."""
    kv_table().put_item(Item={'key': key, _COUNT_COL: 0})


def set_key_expiration(key: str, epoch_seconds: int) -> None:
    """Configure the key to automatically expire at the given time.

    DynamoDB typically deletes expired items within 48 hours of expiration.

    Args:
        key: The name of the counter
        epoch_seconds: When you want the counter to expire (set to 0 to disable)
    """
    kv_table().update_item(Key={'key': key},
                           UpdateExpression='SET expiresAt = :time',
                           ExpressionAttributeValues={':time': epoch_seconds})


def get_string_set(key: str) -> Set[str]:
    """Get a string set's current value (defaulting to empty set if key does not exit)."""
    response = kv_table().get_item(
        Key={'key': key},
        ProjectionExpression=_STRING_SET_COL,
    )
    return response.get('Item', {}).get(_STRING_SET_COL, set())


def put_string_set(key: str, val: Sequence[str]) -> None:
    """Overwrite a string set under the given key.

    This is faster than (reset_string_set + add_string_set) if you know exactly what the contents
    of the set should be.

    Args:
        key: The name of the string set
        val: A list/set/tuple of strings to store
    """
    if len(val) == 0:
        # Can't put an empty string set - remove it instead
        reset_string_set(key)
    else:
        kv_table().put_item(Item={'key': key, _STRING_SET_COL: set(val)})


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
        if len(item_value) == 0:
            # We can't add empty sets, just return the existing value instead
            return get_string_set(key)

    response = kv_table().update_item(
        Key={'key': key},
        ReturnValues='UPDATED_NEW',
        UpdateExpression='ADD #col :ss',
        ExpressionAttributeNames={'#col': _STRING_SET_COL},
        ExpressionAttributeValues={':ss': item_value},
    )
    return response['Attributes'][_STRING_SET_COL]


def remove_from_string_set(key: str, val: Union[str,
                                                Sequence[str]]) -> Set[str]:
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
        if len(item_value) == 0:
            # We can't remove empty sets, just return the existing value instead
            return get_string_set(key)

    response = kv_table().update_item(
        Key={'key': key},
        ReturnValues='UPDATED_NEW',
        UpdateExpression='DELETE #col :ss',
        ExpressionAttributeNames={'#col': _STRING_SET_COL},
        ExpressionAttributeValues={':ss': item_value},
    )
    return response['Attributes'][_STRING_SET_COL]


def reset_string_set(key: str) -> None:
    """Reset a string set to empty."""
    kv_table().update_item(
        Key={'key': key},
        UpdateExpression='REMOVE #col',
        ExpressionAttributeNames={'#col': _STRING_SET_COL},
    )


def aws_strip_role_session_id(user_identity_arn):
    # The ARN structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split('/')
    if arn_parts:
        return '/'.join(arn_parts[:2])
    return user_identity_arn


def evaluate_threshold(key: str,
                       threshold: int = 10,
                       expiry_seconds: int = 3600) -> bool:
    hourly_error_count = increment_counter(key)
    if hourly_error_count == 1:
        set_key_expiration(key, int(time.time()) + expiry_seconds)
    # If it exceeds our threshold, reset and then return an alert
    elif hourly_error_count >= threshold:
        reset_counter(key)
        return True
    return False


# Basic helpers


def pattern_match(string_to_match: str, pattern: str):
    return fnmatch(string_to_match, pattern)


def pattern_match_list(string_to_match: str, patterns: Sequence[str]):
    return any(fnmatch(string_to_match, p) for p in patterns)


def _test_kv_store():
    """Integration tests which validate the functions which interact with the key-value store.

    Deploy Panther and then simply run "python3 panther.py" to test.
    """
    assert increment_counter('panther', 1) == 1
    assert increment_counter('labs', 3) == 3
    assert increment_counter('panther', -2) == -1
    assert increment_counter('panther', 0) == -1
    assert increment_counter('panther', 11) == 10

    assert get_counter('panther') == 10
    assert get_counter('labs') == 3
    assert get_counter('nonexistent') == 0

    reset_counter('panther')
    reset_counter('labs')
    assert get_counter('panther') == 0
    assert get_counter('labs') == 0

    set_key_expiration('panther', int(time.time()))

    # Add elements in a list, tuple, set, or as singleton strings
    # The same key can be used to store int counts and string sets
    assert add_to_string_set('panther', ['a', 'b']) == {'a', 'b'}
    assert add_to_string_set('panther', ['b', 'a']) == {'a', 'b'}
    assert add_to_string_set('panther', 'c') == {'a', 'b', 'c'}
    assert add_to_string_set('panther', set()) == {'a', 'b', 'c'}
    assert add_to_string_set('panther', {'b', 'c', 'd'}) == {'a', 'b', 'c', 'd'}
    assert add_to_string_set('panther', ('d', 'e')) == {'a', 'b', 'c', 'd', 'e'}

    # Empty strings are allowed
    assert add_to_string_set('panther', '') == {'a', 'b', 'c', 'd', 'e', ''}

    assert get_string_set('labs') == set()
    assert get_string_set('panther') == {'a', 'b', 'c', 'd', 'e', ''}

    assert remove_from_string_set('panther', ['b', 'c', 'd']) == {'a', 'e', ''}
    assert remove_from_string_set('panther', '') == {'a', 'e'}
    assert remove_from_string_set('panther', '') == {'a', 'e'}

    # Overwrite contents completely
    put_string_set('panther', ['go', 'python'])
    assert get_string_set('panther') == {'go', 'python'}
    put_string_set('labs', [])
    assert get_string_set('labs') == set()

    reset_string_set('panther')
    reset_string_set('nonexistent')  # no error
    assert get_string_set('panther') == set()


if __name__ == '__main__':
    _test_kv_store()
