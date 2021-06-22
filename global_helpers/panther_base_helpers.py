import json
import re
from collections.abc import Mapping
from fnmatch import fnmatch
from functools import reduce
from ipaddress import ip_address, ip_network
from typing import Sequence

# # # # # # # # # # # # # #
#       Exceptions        #
# # # # # # # # # # # # # #


class PantherUnexpectedAlert(Exception):
    """Error returned when a Panther detection encounters an unexpected situation."""


# # # # # # # # # # # # # #
#   Compliance Helpers    #
# # # # # # # # # # # # # #

# Expects a map with the a Key 'Tags' that maps to a map of key/value string pairs, or None if no
# tags are present.
# All Panther defined resources meet this requirement.
CDE_TAG_KEY = "environment"
CDE_TAG_VALUE = "pci"


# Defaults to True to assume something is in scope if it is not tagged
def in_pci_scope_tags(resource):
    if resource.get("Tags") is None:
        return True
    return resource["Tags"].get(CDE_TAG_KEY) == CDE_TAG_VALUE


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as in scope
PCI_NETWORKS = [
    ip_network("10.0.0.0/24"),
]


def is_pci_scope_cidr(ip_range):
    return any(ip_network(ip_range).overlaps(pci_network) for pci_network in PCI_NETWORKS)


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as DMZ space.
DMZ_NETWORKS = [
    ip_network("10.1.0.0/24"),
    ip_network("100.1.0.0/24"),
]


def is_dmz_cidr(ip_range):
    """This function determines whether a given IP range is within the defined DMZ IP range."""
    return any(ip_network(ip_range).overlaps(dmz_network) for dmz_network in DMZ_NETWORKS)


DMZ_TAG_KEY = "environment"
DMZ_TAG_VALUE = "dmz"


# Defaults to False to assume something is not a DMZ if it is not tagged
def is_dmz_tags(resource):
    """This function determines whether a given resource is tagged as exisitng in a DMZ."""
    if resource["Tags"] is None:
        return False
    return resource["Tags"].get(DMZ_TAG_KEY) == DMZ_TAG_VALUE


# Function variables here so that implementation details of these functions can be changed without
# having to rename the function in all locations its used, or having an outdated name on the actual
# function being used, etc.
IN_PCI_SCOPE = in_pci_scope_tags
IS_DMZ = is_dmz_tags

# # # # # # # # # # # # # #
#      GSuite Helpers     #
# # # # # # # # # # # # # #

GSUITE_PARAMETER_VALUES = [
    "value",
    "intValue",
    "boolValue",
    "multiValue",
    "multiIntValue",
    "messageValue",
    "multiMessageValue",
]


# GSuite parameters are formatted as a list of dictionaries, where each dictionary has a 'name' key
# that maps to the name of the parameter, and one key from GSUITE_PARAMETER_VALUES that maps to the
# value of the parameter. This means to lookup the value of a particular parameter, you must
# traverse the entire list of parameters to find it and then know (or guess) what type of value it
# contains. This helper function handles that for us.
#
# Example parameters list:
# parameters = [
#   {
#       "name": "event_id",
#       "value": "abc123"
#   },
#   {
#       "name": "start_time",
#       "intValue": 63731901000
#   },
#   {
#       "name": "end_time",
#       "intValue": 63731903000
#   },
#   {
#       "name": "things",
#       "multiValue": [ "DRIVE" , "MEME"]
#   }
# ]
def gsuite_parameter_lookup(parameters, key):
    for param in parameters:
        if param["name"] != key:
            continue
        for value in GSUITE_PARAMETER_VALUES:
            if value in param:
                return param[value]
        return None
    return None


# GSuite event details are fomatted as a list of dictionaries. Each entry has a 'type' and 'name'.
#
# In order to find the event details of interest, you must loop through
# the list searching for a particular type and name.
#
# This helper function handles the looping functionality that is common in many of the gsuite rules
def gsuite_details_lookup(detail_type, detail_names, event):
    for details in event.get("events", {}):
        if details.get("type") == detail_type and details.get("name") in detail_names:
            return details
    # not found, return empty dict
    return {}


# # # # # # # # # # # # # #
#      Zendesk Helpers     #
# # # # # # # # # # # # # #
ZENDESK_ROLE_ASSIGNED = r"Role changed from (?P<old_role>.+) to (?P<new_role>[^$]+)"
ZENDESK_LOGIN_EVENT = (
    r"(?P<login_result>[\S]+) sign-in using (?P<authentication_method>.+) from "
    r"(?P<authentication_location>[^$]+)"
)
ZENDESK_TWO_FACTOR_SOURCE = "Two-Factor authentication for all admins and agents"

## key names
ZENDESK_CHANGE_DESCRIPTION = "change_description"


def zendesk_get_roles(event):
    matches = re.search(
        ZENDESK_ROLE_ASSIGNED, event.get(ZENDESK_CHANGE_DESCRIPTION, ""), re.IGNORECASE
    )
    if matches:
        return matches.group("old_role"), matches.group("new_role")
    return None, None


def zendesk_get_authentication_method(event):
    matches = re.search(
        ZENDESK_LOGIN_EVENT, event.get(ZENDESK_CHANGE_DESCRIPTION, ""), re.IGNORECASE
    )
    if matches:
        return matches.group("authentication_method")
    return None


# # # # # # # # # # # # # #
#      Generic Helpers    #
# # # # # # # # # # # # # #


# 'additional_details' from box logs varies by event_type
# but it should be a valid json string. This helper
# wraps the process of extracting those details.
def box_parse_additional_details(event: dict):
    if event.get("additional_details", {}):
        try:
            return json.loads(event.get("additional_details", {}))
        except ValueError:
            return {}
    return {}


def okta_alert_context(event: dict):
    """Returns common context for automation of Okta alerts"""
    return {
        "ips": event.get("p_any_ip_addresses", []),
        "actor": event.get("actor", ""),
        "target": event.get("target", ""),
        "client": event.get("client", ""),
    }


def deep_get(dictionary: dict, *keys, default=None):
    """Safely return the value of an arbitrarily nested map

    Inspired by https://bit.ly/3a0hq9E
    """
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default, keys, dictionary
    )


def aws_strip_role_session_id(user_identity_arn):
    # The ARN structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split("/")
    if arn_parts:
        return "/".join(arn_parts[:2])
    return user_identity_arn


def is_ip_in_network(ip_addr, networks):
    """Check that a given IP is within a list of IP ranges"""
    return any(ip_address(ip_addr) in ip_network(network) for network in networks)


def pattern_match(string_to_match: str, pattern: str):
    """Wrapper around fnmatch for basic pattern globs"""
    return fnmatch(string_to_match, pattern)


def pattern_match_list(string_to_match: str, patterns: Sequence[str]):
    """Check that a string matches any pattern in a given list"""
    return any(fnmatch(string_to_match, p) for p in patterns)


def get_binding_deltas(event):
    """A GCP helper function to return the binding deltas from audit events

    Binding deltas provide context on a permission change, including the
    action, role, and member associated with the request.
    """
    if event.get("protoPayload", {}).get("methodName") != "SetIamPolicy":
        return []

    service_data = event.get("protoPayload", {}).get("serviceData")
    if not service_data:
        return []

    # Reference: bit.ly/2WsJdZS
    binding_deltas = service_data.get("policyDelta", {}).get("bindingDeltas")
    if not binding_deltas:
        return []
    return binding_deltas
