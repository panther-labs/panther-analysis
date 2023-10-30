import base64
import binascii
import json
import re
from collections import OrderedDict
from collections.abc import Mapping
from fnmatch import fnmatch
from functools import reduce
from ipaddress import ip_address, ip_network
from typing import Any, List, Optional, Sequence, Union

# # # # # # # # # # # # # #
#       Exceptions        #
# # # # # # # # # # # # # #


class PantherUnexpectedAlert(Exception):
    """Error returned when a Panther detection encounters an unexpected situation."""


# # # # # # # # # # # # # #
#   Compliance Helpers    #
# # # # # # # # # # # # # #

# Expects a map with a Key 'Tags' that maps to a map of key/value string pairs, or None if no
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
    """This function determines whether a given resource is tagged as existing in a DMZ."""
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


# GSuite event details are formatted as a list of dictionaries. Each entry has a 'type' and 'name'.
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

# key names
ZENDESK_CHANGE_DESCRIPTION = "change_description"
ZENDESK_APP_ROLE_ASSIGNED = re.compile(
    r"(?P<app>.*) role changed from (?P<old_role>.+) to (?P<new_role>.*)", re.IGNORECASE
)
ZENDESK_ROLE_ASSIGNED = re.compile(
    r"Role changed from (?P<old_role>.+) to (?P<new_role>[^$]+)", re.IGNORECASE
)


def zendesk_get_roles(event):
    old_role = ""
    new_role = ""
    role_change = event.get(ZENDESK_CHANGE_DESCRIPTION, "")
    if "\n" in role_change:
        for app_change in role_change.split("\n"):
            matches = ZENDESK_APP_ROLE_ASSIGNED.match(app_change)
            if matches:
                if old_role:
                    old_role += " ; "
                old_role += matches.group("app") + ":" + matches.group("old_role")
                if new_role:
                    new_role += " ; "
                new_role += matches.group("app") + ":" + matches.group("new_role")
    else:
        matches = ZENDESK_ROLE_ASSIGNED.match(role_change)
        if matches:
            old_role = matches.group("old_role")
            new_role = matches.group("new_role")
    if not old_role:
        old_role = "<UNKNOWN_APP>:<UNKNOWN_ROLE>"
    if not new_role:
        new_role = "<UNKNOWN_APP>:<UNKNOWN_ROLE>"
    return old_role, new_role


# # # # # # # # # # # # # #
#      Generic Helpers    #
# # # # # # # # # # # # # #


# 'additional_details' from box logs varies by event_type.
# This helper wraps the process of extracting those details.
def box_parse_additional_details(event: dict):
    additional_details = event.get("additional_details", {})
    if isinstance(additional_details, (str, bytes)):
        try:
            return json.loads(additional_details)
        except ValueError:
            return {}
    return additional_details


def okta_alert_context(event: dict):
    """Returns common context for automation of Okta alerts"""
    return {
        "event_type": event.get("eventtype", ""),
        "severity": event.get("severity", ""),
        "actor": event.get("actor", {}),
        "client": event.get("client", {}),
        "request": event.get("request", {}),
        "outcome": event.get("outcome", {}),
        "target": event.get("target", []),
        "debug_context": event.get("debugcontext", {}),
        "authentication_context": event.get("authenticationcontext", {}),
        "security_context": event.get("securitycontext", {}),
        "ips": event.get("p_any_ip_addresses", []),
    }


def crowdstrike_detection_alert_context(event: dict):
    """Returns common context for Crowdstrike detections"""
    return {
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "user": get_crowdstrike_field(event, "UserName", default=""),
        "console-link": get_crowdstrike_field(event, "FalconHostLink", default=""),
        "commandline": get_crowdstrike_field(event, "CommandLine", default=""),
        "parentcommandline": get_crowdstrike_field(event, "ParentCommandLine", default=""),
        "filename": get_crowdstrike_field(event, "FileName", default=""),
        "filepath": get_crowdstrike_field(event, "FilePath", default=""),
        "description": get_crowdstrike_field(event, "DetectDescription", default=""),
        "action": get_crowdstrike_field(event, "PatternDispositionDescription", default=""),
    }


def crowdstrike_process_alert_context(event: dict):
    """Returns common process context for Crowdstrike detections"""
    return {
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "CommandLine": get_crowdstrike_field(event, "CommandLine", default=""),
        "TargetProcessId": get_crowdstrike_field(event, "TargetProcessId", default=""),
        "RawProcessId": get_crowdstrike_field(event, "RawProcessId", default=""),
        "ParentBaseFileName": get_crowdstrike_field(event, "ParentBaseFileName", default=""),
        "ParentProcessId": get_crowdstrike_field(event, "ParentProcessId", default=""),
        "ImageFileName": get_crowdstrike_field(event, "ImageFileName", default=""),
        "SHA256Hash": get_crowdstrike_field(event, "SHA256HashData", default=""),
        "platform": get_crowdstrike_field(event, "event_platform", default=""),
    }


def crowdstrike_network_detection_alert_context(event: dict):
    """Returns common network context for Crowdstrike detections"""
    return {
        "LocalAddressIP4": get_crowdstrike_field(event, "LocalAddressIP4", default=""),
        "LocalPort": get_crowdstrike_field(event, "LocalPort", default=""),
        "RemoteAddressIP4": get_crowdstrike_field(event, "RemoteAddressIP4", default=""),
        "RemotePort": get_crowdstrike_field(event, "RemotePort", default=""),
        "Protocol": get_crowdstrike_field(event, "Protocol", default=""),
        "event_simpleName": get_crowdstrike_field(event, "event_simpleName", default=""),
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "ContextProcessId": get_crowdstrike_field(event, "ContextProcessId", default=""),
    }


def filter_crowdstrike_fdr_event_type(event, name: str) -> bool:
    """
    Checks if the event belongs to the Crowdstrike.FDREvent log type
    and the event type is not the name parameter.
    """
    if event.get("p_log_type") != "Crowdstrike.FDREvent":
        return False
    return event.get("fdr_event_type", "") != name


def get_crowdstrike_field(event, field_name, default=None):
    return (
        deep_get(event, field_name)
        or deep_get(event, "event", field_name)
        or deep_get(event, "unknown_payload", field_name)
        or default
    )


def slack_alert_context(event: dict):
    return {
        "actor-name": deep_get(event, "actor", "user", "name", default="<MISSING_NAME>"),
        "actor-email": deep_get(event, "actor", "user", "email", default="<MISSING_EMAIL>"),
        "actor-ip": deep_get(event, "context", "ip_address", default="<MISSING_IP>"),
        "user-agent": deep_get(event, "context", "ua", default="<MISSING_UA>"),
    }


def github_alert_context(event: dict):
    return {
        "action": event.get("action", ""),
        "actor": event.get("actor", ""),
        "actor_location": deep_get(event, "actor_location", "country_code"),
        "org": event.get("org", ""),
        "repo": event.get("repo", ""),
        "user": event.get("user", ""),
    }


def deep_get(dictionary: dict, *keys, default=None):
    """Safely return the value of an arbitrarily nested map

    Inspired by https://bit.ly/3a0hq9E
    """
    out = reduce(
        lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default, keys, dictionary
    )
    if out is None:
        return default
    return out


# pylint: disable=too-complex,too-many-return-statements
def deep_walk(
    obj: Optional[Any], *keys: str, default: Optional[str] = None, return_val: str = "all"
) -> Union[Optional[Any], Optional[List[Any]]]:
    """Safely retrieve a value stored in complex dictionary structure

    Similar to deep_get but supports accessing dictionary keys within nested lists as well

    Parameters:
    obj (any): the original log event passed to rule(event)
               and nested objects retrieved recursively
    keys (str): comma-separated list of keys used to traverse the event object
    default (str): the default value to return if the desired key's value is not present
    return_val (str): string specifying which value to return
                      possible values are "first", "last", or "all"

    Returns:
    any | list[any]: A single value if return_val is "first", "last",
                     or if "all" is a list containing one element,
                     otherwise a list of values
    """

    def _empty_list(sub_obj: Any):
        return (
            all(_empty_list(next_obj) for next_obj in sub_obj)
            if isinstance(sub_obj, Sequence) and not isinstance(sub_obj, str)
            else False
        )

    if not keys:
        return default if _empty_list(obj) else obj

    current_key = keys[0]
    found: OrderedDict = OrderedDict()

    if isinstance(obj, Mapping):
        next_key = obj.get(current_key, None)
        return (
            deep_walk(next_key, *keys[1:], default=default, return_val=return_val)
            if next_key is not None
            else default
        )
    if isinstance(obj, Sequence) and not isinstance(obj, str):
        for item in obj:
            value = deep_walk(item, *keys, default=default, return_val=return_val)
            if value is not None:
                if isinstance(value, Sequence) and not isinstance(value, str):
                    for sub_item in value:
                        found[sub_item] = None
                else:
                    found[value] = None

    found_list: list[Any] = list(found.keys())
    if not found_list:
        return default
    return {
        "first": found_list[0],
        "last": found_list[-1],
        "all": found_list[0] if len(found_list) == 1 else found_list,
    }.get(return_val, "all")


def get_val_from_list(list_of_dicts, return_field_key, field_cmp_key, field_cmp_val):
    """Return a specific field in a list of Python dictionaries.
    We return the empty set if the comparison key is not found"""
    values_of_return_field = set()
    for item in list_of_dicts:
        if item.get(field_cmp_key) == field_cmp_val:
            values_of_return_field.add(item.get(return_field_key))
    return values_of_return_field


def aws_strip_role_session_id(user_identity_arn):
    # The ARN structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split("/")
    if arn_parts:
        return "/".join(arn_parts[:2])
    return user_identity_arn


def aws_rule_context(event: dict):
    return {
        "eventName": event.get("eventName", "<MISSING_EVENT_NAME>"),
        "eventSource": event.get("eventSource", "<MISSING_ACCOUNT_ID>"),
        "awsRegion": event.get("awsRegion", "<MISSING_AWS_REGION>"),
        "recipientAccountId": event.get("recipientAccountId", "<MISSING_ACCOUNT_ID>"),
        "sourceIPAddress": event.get("sourceIPAddress", "<MISSING_SOURCE_IP>"),
        "userAgent": event.get("userAgent", "<MISSING_USER_AGENT>"),
        "userIdentity": event.get("userIdentity", "<MISSING_USER_IDENTITY>"),
    }


def aws_guardduty_context(event: dict):
    return {
        "description": event.get("description", "<MISSING DESCRIPTION>"),
        "severity": event.get("severity", "<MISSING SEVERITY>"),
        "id": event.get("id", "<MISSING ID>"),
        "type": event.get("type", "<MISSING TYPE>"),
        "resource": event.get("resource", {}),
        "service": event.get("service", {}),
    }


def eks_panther_obj_ref(event: dict):
    user = deep_get(event, "user", "username", default="<NO_USERNAME>")
    source_ips = event.get("sourceIPs", ["0.0.0.0"])  # nosec
    verb = event.get("verb", "<NO_VERB>")
    obj_name = deep_get(event, "objectRef", "name", default="<NO_OBJECT_NAME>")
    obj_ns = deep_get(event, "objectRef", "namespace", default="<NO_OBJECT_NAMESPACE>")
    obj_res = deep_get(event, "objectRef", "resource", default="<NO_OBJECT_RESOURCE>")
    obj_subres = deep_get(event, "objectRef", "subresource", default="")
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL>")
    if obj_subres:
        obj_res = "/".join([obj_res, obj_subres])
    return {
        "actor": user,
        "ns": obj_ns,
        "object": obj_name,
        "resource": obj_res,
        "sourceIPs": source_ips,
        "verb": verb,
        "p_source_label": p_source_label,
    }


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


def msft_graph_alert_context(event):
    return {
        "category": event.get("category", ""),
        "description": event.get("description", ""),
        "userstates": event.get("userstates", []),
    }


def m365_alert_context(event):
    return {
        "operation": event.get("Operation", ""),
        "organization_id": event.get("OrganizationId", ""),
        "client_ip": event.get("ClientIp", ""),
        "extended_properties": event.get("ExtendedProperties", []),
        "modified_properties": event.get("ModifiedProperties", []),
        "application": event.get("Application", ""),
        "actor": event.get("Actor", []),
    }


def defang_ioc(ioc):
    """return defanged IOC from 1.1.1.1 to 1[.]1[.]1[.]1"""
    return ioc.replace(".", "[.]")

# Adapted from https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
def aws_key_account_id(aws_key: str):
    """retrieve the AWS account ID associated with a given access key ID"""
    key_no_prefix = aws_key[4:] # remove the four-character prefix
    base32_key = base64.b32decode(key_no_prefix) # remainder of the key is base32-encoded
    decoded_key = base32_key[0:6] # retrieve the 10-byte string

    # Convert the 10-byte string to an integer
    key_id_int = int.from_bytes(decoded_key, byteorder='big', signed=False)
    mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)

    # Do a bitwise AND with the mask to retrieve the account ID (divide the 10-byte key integer by 128 and remove the fractional part(s))
    account_id = (key_id_int & mask)>>7
    return str(account_id)
