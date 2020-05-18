"""Utility functions provided to policies and rules during execution."""
from ipaddress import ip_network
from typing import Any, Dict

import boto3
from boto3.dynamodb.conditions import Attr
import botocore

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


_KV_TABLE = None
_COUNT_COL = 'intCount'  # name of the count column


def kv_table() -> boto3.resource:
    """Lazily build key-value table resource"""
    # pylint: disable=global-statement
    global _KV_TABLE
    if not _KV_TABLE:
        # pylint: disable=no-member
        _KV_TABLE = boto3.resource('dynamodb').Table('panther-kv-store')
    return _KV_TABLE


def get_counter(key: str) -> int:
    """Get a counter's current value (defaulting to 0 if key does not exit)."""
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
    table = kv_table()
    try:
        response = table.update_item(
            Key={'key': key},
            ReturnValues='UPDATED_NEW',
            # You can only increment attributes which already exist
            ConditionExpression=Attr(_COUNT_COL).exists(),
            UpdateExpression='SET #col = intCount + :incr',
            ExpressionAttributeNames={'#col': _COUNT_COL},
            ExpressionAttributeValues={':incr': val})

        # Numeric values are returned as decimal.Decimal
        return response['Attributes'][_COUNT_COL].to_integral_value()
    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] != 'ConditionalCheckFailedException':
            raise

    # The conditional check failed, meaning this item doesn't exist yet. Add it!
    table.put_item(Item={'key': key, _COUNT_COL: val})
    return val


def reset_counter(key: str) -> None:
    """Reset a counter to 0."""
    kv_table().put_item(Item={'key': key, _COUNT_COL: 0})


def set_counter_expiration(key: str, epoch_seconds: int) -> None:
    """Configure the counter to automatically expire at the given time.

    DynamoDB typically deletes expired items within 48 hours of expiration.

    Args:
        key: The name of the counter
        epoch_seconds: When you want the counter to expire (set to 0 to disable)
    """
    kv_table().update_item(Key={'key': key},
                           UpdateExpression='SET expiresAt = :time',
                           ExpressionAttributeValues={':time': epoch_seconds})
