"""Utility functions provided to policies and rules during execution."""
import os
from typing import Any, Dict
from ipaddress import ip_network
import boto3

# Default to us-east-1 so this doesn't fail during CI (env variable is not always present in CI)
# Used to communicate directly with the Panther resource data store
# pylint: disable=no-member
TABLE = boto3.resource('dynamodb',
                       os.environ.get('AWS_DEFAULT_REGION',
                                      'us-east-1')).Table('panther-resources')
# pylint: enable=no-member


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


def dynamo_lookup(key: str) -> Dict[str, Any]:
    """Make a dynamodb GetItem API call."""
    return TABLE.get_item(Key={'id': key})


def resource_lookup(resource_id: str) -> Dict[str, Any]:
    """This function is used to get a resource from the resources-api based on its resourceID."""
    # Validate input so we can provide meaningful error messages to users
    if resource_id == '':
        raise PantherBadInput('resourceId cannot be blank')

    # Get the item from dynamo
    response = dynamo_lookup(resource_id)

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
