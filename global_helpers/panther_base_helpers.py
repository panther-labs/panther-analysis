import json
import re
from base64 import b64decode
from binascii import Error as AsciiError
from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime
from fnmatch import fnmatch
from functools import reduce
from ipaddress import ip_address, ip_network
from typing import Any, List, Optional, Sequence, Union

from panther_config import config

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


PCI_NETWORKS = config.PCI_NETWORKS


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as in scope
def is_pci_scope_cidr(ip_range):
    return any(ip_network(ip_range).overlaps(pci_network) for pci_network in PCI_NETWORKS)


DMZ_NETWORKS = config.DMZ_NETWORKS


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as DMZ space.
def is_dmz_cidr(ip_range):
    """This function determines whether a given IP range is within the defined DMZ IP range."""
    return any(ip_network(ip_range).overlaps(dmz_network) for dmz_network in DMZ_NETWORKS)


# Defaults to False to assume something is not a DMZ if it is not tagged
def is_dmz_tags(resource, dmz_tags):
    """This function determines whether a given resource is tagged as existing in a DMZ."""
    if resource["Tags"] is None:
        return False
    for key, value in dmz_tags:
        if resource["Tags"].get(key) == value:
            return True
    return False


# Function variables here so that implementation details of these functions can be changed without
# having to rename the function in all locations its used, or having an outdated name on the actual
# function being used, etc.
IN_PCI_SCOPE = in_pci_scope_tags

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
        "userStates": event.get("userStates", []),
        "fileStates": event.get("fileStates", []),
        "hostStates": event.get("hostStates", []),
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


def panther_nanotime_to_python_datetime(panther_time: str) -> datetime:
    panther_time_micros = re.search(r"\.(\d+)", panther_time).group(1)
    panther_time_micros_rounded = panther_time_micros[0:6]
    panther_time_rounded = re.sub(r"\.\d+", f".{panther_time_micros_rounded}", panther_time)
    panther_time_format = r"%Y-%m-%d %H:%M:%S.%f"
    return datetime.strptime(panther_time_rounded, panther_time_format)


def golang_nanotime_to_python_datetime(golang_time: str) -> datetime:
    golang_time_format = r"%Y-%m-%dT%H:%M:%S.%fZ"
    # Golang fractional seconds include a mix of microseconds and
    # nanoseconds, which doesn't play well with Python's microseconds datetimes.
    # This rounds the fractional seconds to a microsecond-size.
    golang_time_micros = re.search(r"\.(\d+)Z", golang_time).group(1)
    golang_time_micros_rounded = golang_time_micros[0:6]
    golang_time_rounded = re.sub(r"\.\d+Z", f".{golang_time_micros_rounded}Z", golang_time)
    return datetime.strptime(golang_time_rounded, golang_time_format)


def is_base64(b64: str) -> str:
    # if the string is base64 encoded, return the decoded ASCII string
    # otherwise return an empty string
    # handle false positives for very short strings
    if len(b64) < 12:
        return ""
    # Pad args with "=" to ensure proper decoding
    b64 = b64.ljust((len(b64) + 3) // 4 * 4, "=")
    # Check if the matched string can be decoded back into ASCII
    try:
        return b64decode(b64, validate=True).decode("ascii")
    except AsciiError:
        pass
    except UnicodeDecodeError:
        pass
    return ""


def key_value_list_to_dict(list_objects: List[dict], key: str, value: str) -> dict:
    # Convert a list of dictionaries to a single dictionary
    # example: [{'key': 'a', 'value': 1}, {'key': 'b', 'value': 2}]
    # becomes: {'a': 1, 'b': 2}
    return {item[key]: item[value] for item in list_objects}

def expand_country_code(code: str | int) -> str:
    """Given an abbreviated country code (alpha-2, alpha-3, or numeric), returns the full country
    name.
    
    Args:
        code (str, int): Either an apha-2 (US), an alpha-3 (USA), or numeric (840) country code
    Ref:
        https://www.iban.com/country-codes
    """
    codes = {
        'AF': 'Afghanistan',
        'AFG': 'Afghanistan',
        '004': 'Afghanistan',
        4: 'Afghanistan',
        'AX': 'Åland Islands',
        'ALA': 'Åland Islands',
        '248': 'Åland Islands',
        248: 'Åland Islands',
        'AL': 'Albania',
        'ALB': 'Albania',
        '008': 'Albania',
        8: 'Albania',
        'DZ': 'Algeria',
        'DZA': 'Algeria',
        '012': 'Algeria',
        12: 'Algeria',
        'AS': 'American Samoa',
        'ASM': 'American Samoa',
        '016': 'American Samoa',
        16: 'American Samoa',
        'AD': 'Andorra',
        'AND': 'Andorra',
        '020': 'Andorra',
        20: 'Andorra',
        'AO': 'Angola',
        'AGO': 'Angola',
        '024': 'Angola',
        24: 'Angola',
        'AI': 'Anguilla',
        'AIA': 'Anguilla',
        '660': 'Anguilla',
        660: 'Anguilla',
        'AQ': 'Antarctica',
        'ATA': 'Antarctica',
        '010': 'Antarctica',
        10: 'Antarctica',
        'AG': 'Antigua and Barbuda',
        'ATG': 'Antigua and Barbuda',
        '028': 'Antigua and Barbuda',
        28: 'Antigua and Barbuda',
        'AR': 'Argentina',
        'ARG': 'Argentina',
        '032': 'Argentina',
        32: 'Argentina',
        'AM': 'Armenia',
        'ARM': 'Armenia',
        '051': 'Armenia',
        51: 'Armenia',
        'AW': 'Aruba',
        'ABW': 'Aruba',
        '533': 'Aruba',
        533: 'Aruba',
        'AU': 'Australia',
        'AUS': 'Australia',
        '036': 'Australia',
        36: 'Australia',
        'AT': 'Austria',
        'AUT': 'Austria',
        '040': 'Austria',
        40: 'Austria',
        'AZ': 'Azerbaijan',
        'AZE': 'Azerbaijan',
        '031': 'Azerbaijan',
        31: 'Azerbaijan',
        'BS': 'Bahamas',
        'BHS': 'Bahamas',
        '044': 'Bahamas',
        44: 'Bahamas',
        'BH': 'Bahrain',
        'BHR': 'Bahrain',
        '048': 'Bahrain',
        48: 'Bahrain',
        'BD': 'Bangladesh',
        'BGD': 'Bangladesh',
        '050': 'Bangladesh',
        50: 'Bangladesh',
        'BB': 'Barbados',
        'BRB': 'Barbados',
        '052': 'Barbados',
        52: 'Barbados',
        'BY': 'Belarus',
        'BLR': 'Belarus',
        '112': 'Belarus',
        112: 'Belarus',
        'BE': 'Belgium',
        'BEL': 'Belgium',
        '056': 'Belgium',
        56: 'Belgium',
        'BZ': 'Belize',
        'BLZ': 'Belize',
        '084': 'Belize',
        84: 'Belize',
        'BJ': 'Benin',
        'BEN': 'Benin',
        '204': 'Benin',
        204: 'Benin',
        'BM': 'Bermuda',
        'BMU': 'Bermuda',
        '060': 'Bermuda',
        60: 'Bermuda',
        'BT': 'Bhutan',
        'BTN': 'Bhutan',
        '064': 'Bhutan',
        64: 'Bhutan',
        'BO': 'Bolivia, Plurinational State of',
        'BOL': 'Bolivia, Plurinational State of',
        '068': 'Bolivia, Plurinational State of',
        68: 'Bolivia, Plurinational State of',
        'BQ': 'Bonaire, Sint Eustatius and Saba',
        'BES': 'Bonaire, Sint Eustatius and Saba',
        '535': 'Bonaire, Sint Eustatius and Saba',
        535: 'Bonaire, Sint Eustatius and Saba',
        'BA': 'Bosnia and Herzegovina',
        'BIH': 'Bosnia and Herzegovina',
        '070': 'Bosnia and Herzegovina',
        70: 'Bosnia and Herzegovina',
        'BW': 'Botswana',
        'BWA': 'Botswana',
        '072': 'Botswana',
        72: 'Botswana',
        'BV': 'Bouvet Island',
        'BVT': 'Bouvet Island',
        '074': 'Bouvet Island',
        74: 'Bouvet Island',
        'BR': 'Brazil',
        'BRA': 'Brazil',
        '076': 'Brazil',
        76: 'Brazil',
        'IO': 'British Indian Ocean Territory',
        'IOT': 'British Indian Ocean Territory',
        '086': 'British Indian Ocean Territory',
        86: 'British Indian Ocean Territory',
        'BN': 'Brunei Darussalam',
        'BRN': 'Brunei Darussalam',
        '096': 'Brunei Darussalam',
        96: 'Brunei Darussalam',
        'BG': 'Bulgaria',
        'BGR': 'Bulgaria',
        '100': 'Bulgaria',
        100: 'Bulgaria',
        'BF': 'Burkina Faso',
        'BFA': 'Burkina Faso',
        '854': 'Burkina Faso',
        854: 'Burkina Faso',
        'BI': 'Burundi',
        'BDI': 'Burundi',
        '108': 'Burundi',
        108: 'Burundi',
        'CV': 'Cabo Verde',
        'CPV': 'Cabo Verde',
        '132': 'Cabo Verde',
        132: 'Cabo Verde',
        'KH': 'Cambodia',
        'KHM': 'Cambodia',
        '116': 'Cambodia',
        116: 'Cambodia',
        'CM': 'Cameroon',
        'CMR': 'Cameroon',
        '120': 'Cameroon',
        120: 'Cameroon',
        'CA': 'Canada',
        'CAN': 'Canada',
        '124': 'Canada',
        124: 'Canada',
        'KY': 'Cayman Islands',
        'CYM': 'Cayman Islands',
        '136': 'Cayman Islands',
        136: 'Cayman Islands',
        'CF': 'Central African Republic',
        'CAF': 'Central African Republic',
        '140': 'Central African Republic',
        140: 'Central African Republic',
        'TD': 'Chad',
        'TCD': 'Chad',
        '148': 'Chad',
        148: 'Chad',
        'CL': 'Chile',
        'CHL': 'Chile',
        '152': 'Chile',
        152: 'Chile',
        'CN': 'China',
        'CHN': 'China',
        '156': 'China',
        156: 'China',
        'CX': 'Christmas Island',
        'CXR': 'Christmas Island',
        '162': 'Christmas Island',
        162: 'Christmas Island',
        'CC': 'Cocos (Keeling) Islands',
        'CCK': 'Cocos (Keeling) Islands',
        '166': 'Cocos (Keeling) Islands',
        166: 'Cocos (Keeling) Islands',
        'CO': 'Colombia',
        'COL': 'Colombia',
        '170': 'Colombia',
        170: 'Colombia',
        'KM': 'Comoros',
        'COM': 'Comoros',
        '174': 'Comoros',
        174: 'Comoros',
        'CG': 'Congo',
        'COG': 'Congo',
        '178': 'Congo',
        178: 'Congo',
        'CD': 'Congo, Democratic Republic of the',
        'COD': 'Congo, Democratic Republic of the',
        '180': 'Congo, Democratic Republic of the',
        180: 'Congo, Democratic Republic of the',
        'CK': 'Cook Islands',
        'COK': 'Cook Islands',
        '184': 'Cook Islands',
        184: 'Cook Islands',
        'CR': 'Costa Rica',
        'CRI': 'Costa Rica',
        '188': 'Costa Rica',
        188: 'Costa Rica',
        'CI': "Côte d'Ivoire",
        'CIV': "Côte d'Ivoire",
        '384': "Côte d'Ivoire",
        384: "Côte d'Ivoire",
        'HR': 'Croatia',
        'HRV': 'Croatia',
        '191': 'Croatia',
        191: 'Croatia',
        'CU': 'Cuba',
        'CUB': 'Cuba',
        '192': 'Cuba',
        192: 'Cuba',
        'CW': 'Curaçao',
        'CUW': 'Curaçao',
        '531': 'Curaçao',
        531: 'Curaçao',
        'CY': 'Cyprus',
        'CYP': 'Cyprus',
        '196': 'Cyprus',
        196: 'Cyprus',
        'CZ': 'Czechia',
        'CZE': 'Czechia',
        '203': 'Czechia',
        203: 'Czechia',
        'DK': 'Denmark',
        'DNK': 'Denmark',
        '208': 'Denmark',
        208: 'Denmark',
        'DJ': 'Djibouti',
        'DJI': 'Djibouti',
        '262': 'Djibouti',
        262: 'Djibouti',
        'DM': 'Dominica',
        'DMA': 'Dominica',
        '212': 'Dominica',
        212: 'Dominica',
        'DO': 'Dominican Republic',
        'DOM': 'Dominican Republic',
        '214': 'Dominican Republic',
        214: 'Dominican Republic',
        'EC': 'Ecuador',
        'ECU': 'Ecuador',
        '218': 'Ecuador',
        218: 'Ecuador',
        'EG': 'Egypt',
        'EGY': 'Egypt',
        '818': 'Egypt',
        818: 'Egypt',
        'SV': 'El Salvador',
        'SLV': 'El Salvador',
        '222': 'El Salvador',
        222: 'El Salvador',
        'GQ': 'Equatorial Guinea',
        'GNQ': 'Equatorial Guinea',
        '226': 'Equatorial Guinea',
        226: 'Equatorial Guinea',
        'ER': 'Eritrea',
        'ERI': 'Eritrea',
        '232': 'Eritrea',
        232: 'Eritrea',
        'EE': 'Estonia',
        'EST': 'Estonia',
        '233': 'Estonia',
        233: 'Estonia',
        'SZ': 'Eswatini',
        'SWZ': 'Eswatini',
        '748': 'Eswatini',
        748: 'Eswatini',
        'ET': 'Ethiopia',
        'ETH': 'Ethiopia',
        '231': 'Ethiopia',
        231: 'Ethiopia',
        'FK': 'Falkland Islands (Malvinas)',
        'FLK': 'Falkland Islands (Malvinas)',
        '238': 'Falkland Islands (Malvinas)',
        238: 'Falkland Islands (Malvinas)',
        'FO': 'Faroe Islands',
        'FRO': 'Faroe Islands',
        '234': 'Faroe Islands',
        234: 'Faroe Islands',
        'FJ': 'Fiji',
        'FJI': 'Fiji',
        '242': 'Fiji',
        242: 'Fiji',
        'FI': 'Finland',
        'FIN': 'Finland',
        '246': 'Finland',
        246: 'Finland',
        'FR': 'France',
        'FRA': 'France',
        '250': 'France',
        250: 'France',
        'GF': 'French Guiana',
        'GUF': 'French Guiana',
        '254': 'French Guiana',
        254: 'French Guiana',
        'PF': 'French Polynesia',
        'PYF': 'French Polynesia',
        '258': 'French Polynesia',
        258: 'French Polynesia',
        'TF': 'French Southern Territories',
        'ATF': 'French Southern Territories',
        '260': 'French Southern Territories',
        260: 'French Southern Territories',
        'GA': 'Gabon',
        'GAB': 'Gabon',
        '266': 'Gabon',
        266: 'Gabon',
        'GM': 'Gambia',
        'GMB': 'Gambia',
        '270': 'Gambia',
        270: 'Gambia',
        'GE': 'Georgia',
        'GEO': 'Georgia',
        '268': 'Georgia',
        268: 'Georgia',
        'DE': 'Germany',
        'DEU': 'Germany',
        '276': 'Germany',
        276: 'Germany',
        'GH': 'Ghana',
        'GHA': 'Ghana',
        '288': 'Ghana',
        288: 'Ghana',
        'GI': 'Gibraltar',
        'GIB': 'Gibraltar',
        '292': 'Gibraltar',
        292: 'Gibraltar',
        'GR': 'Greece',
        'GRC': 'Greece',
        '300': 'Greece',
        300: 'Greece',
        'GL': 'Greenland',
        'GRL': 'Greenland',
        '304': 'Greenland',
        304: 'Greenland',
        'GD': 'Grenada',
        'GRD': 'Grenada',
        '308': 'Grenada',
        308: 'Grenada',
        'GP': 'Guadeloupe',
        'GLP': 'Guadeloupe',
        '312': 'Guadeloupe',
        312: 'Guadeloupe',
        'GU': 'Guam',
        'GUM': 'Guam',
        '316': 'Guam',
        316: 'Guam',
        'GT': 'Guatemala',
        'GTM': 'Guatemala',
        '320': 'Guatemala',
        320: 'Guatemala',
        'GG': 'Guernsey',
        'GGY': 'Guernsey',
        '831': 'Guernsey',
        831: 'Guernsey',
        'GN': 'Guinea',
        'GIN': 'Guinea',
        '324': 'Guinea',
        324: 'Guinea',
        'GW': 'Guinea-Bissau',
        'GNB': 'Guinea-Bissau',
        '624': 'Guinea-Bissau',
        624: 'Guinea-Bissau',
        'GY': 'Guyana',
        'GUY': 'Guyana',
        '328': 'Guyana',
        328: 'Guyana',
        'HT': 'Haiti',
        'HTI': 'Haiti',
        '332': 'Haiti',
        332: 'Haiti',
        'HM': 'Heard Island and McDonald Islands',
        'HMD': 'Heard Island and McDonald Islands',
        '334': 'Heard Island and McDonald Islands',
        334: 'Heard Island and McDonald Islands',
        'VA': 'Holy See',
        'VAT': 'Holy See',
        '336': 'Holy See',
        336: 'Holy See',
        'HN': 'Honduras',
        'HND': 'Honduras',
        '340': 'Honduras',
        340: 'Honduras',
        'HK': 'Hong Kong',
        'HKG': 'Hong Kong',
        '344': 'Hong Kong',
        344: 'Hong Kong',
        'HU': 'Hungary',
        'HUN': 'Hungary',
        '348': 'Hungary',
        348: 'Hungary',
        'IS': 'Iceland',
        'ISL': 'Iceland',
        '352': 'Iceland',
        352: 'Iceland',
        'IN': 'India',
        'IND': 'India',
        '356': 'India',
        356: 'India',
        'ID': 'Indonesia',
        'IDN': 'Indonesia',
        '360': 'Indonesia',
        360: 'Indonesia',
        'IR': 'Iran, Islamic Republic of',
        'IRN': 'Iran, Islamic Republic of',
        '364': 'Iran, Islamic Republic of',
        364: 'Iran, Islamic Republic of',
        'IQ': 'Iraq',
        'IRQ': 'Iraq',
        '368': 'Iraq',
        368: 'Iraq',
        'IE': 'Ireland',
        'IRL': 'Ireland',
        '372': 'Ireland',
        372: 'Ireland',
        'IM': 'Isle of Man',
        'IMN': 'Isle of Man',
        '833': 'Isle of Man',
        833: 'Isle of Man',
        'IL': 'Israel',
        'ISR': 'Israel',
        '376': 'Israel',
        376: 'Israel',
        'IT': 'Italy',
        'ITA': 'Italy',
        '380': 'Italy',
        380: 'Italy',
        'JM': 'Jamaica',
        'JAM': 'Jamaica',
        '388': 'Jamaica',
        388: 'Jamaica',
        'JP': 'Japan',
        'JPN': 'Japan',
        '392': 'Japan',
        392: 'Japan',
        'JE': 'Jersey',
        'JEY': 'Jersey',
        '832': 'Jersey',
        832: 'Jersey',
        'JO': 'Jordan',
        'JOR': 'Jordan',
        '400': 'Jordan',
        400: 'Jordan',
        'KZ': 'Kazakhstan',
        'KAZ': 'Kazakhstan',
        '398': 'Kazakhstan',
        398: 'Kazakhstan',
        'KE': 'Kenya',
        'KEN': 'Kenya',
        '404': 'Kenya',
        404: 'Kenya',
        'KI': 'Kiribati',
        'KIR': 'Kiribati',
        '296': 'Kiribati',
        296: 'Kiribati',
        'KP': "Korea, Democratic People's Republic of",
        'PRK': "Korea, Democratic People's Republic of",
        '408': "Korea, Democratic People's Republic of",
        408: "Korea, Democratic People's Republic of",
        'KR': 'Korea, Republic of',
        'KOR': 'Korea, Republic of',
        '410': 'Korea, Republic of',
        410: 'Korea, Republic of',
        'KW': 'Kuwait',
        'KWT': 'Kuwait',
        '414': 'Kuwait',
        414: 'Kuwait',
        'KG': 'Kyrgyzstan',
        'KGZ': 'Kyrgyzstan',
        '417': 'Kyrgyzstan',
        417: 'Kyrgyzstan',
        'LA': "Lao People's Democratic Republic",
        'LAO': "Lao People's Democratic Republic",
        '418': "Lao People's Democratic Republic",
        418: "Lao People's Democratic Republic",
        'LV': 'Latvia',
        'LVA': 'Latvia',
        '428': 'Latvia',
        428: 'Latvia',
        'LB': 'Lebanon',
        'LBN': 'Lebanon',
        '422': 'Lebanon',
        422: 'Lebanon',
        'LS': 'Lesotho',
        'LSO': 'Lesotho',
        '426': 'Lesotho',
        426: 'Lesotho',
        'LR': 'Liberia',
        'LBR': 'Liberia',
        '430': 'Liberia',
        430: 'Liberia',
        'LY': 'Libya',
        'LBY': 'Libya',
        '434': 'Libya',
        434: 'Libya',
        'LI': 'Liechtenstein',
        'LIE': 'Liechtenstein',
        '438': 'Liechtenstein',
        438: 'Liechtenstein',
        'LT': 'Lithuania',
        'LTU': 'Lithuania',
        '440': 'Lithuania',
        440: 'Lithuania',
        'LU': 'Luxembourg',
        'LUX': 'Luxembourg',
        '442': 'Luxembourg',
        442: 'Luxembourg',
        'MO': 'Macao',
        'MAC': 'Macao',
        '446': 'Macao',
        446: 'Macao',
        'MG': 'Madagascar',
        'MDG': 'Madagascar',
        '450': 'Madagascar',
        450: 'Madagascar',
        'MW': 'Malawi',
        'MWI': 'Malawi',
        '454': 'Malawi',
        454: 'Malawi',
        'MY': 'Malaysia',
        'MYS': 'Malaysia',
        '458': 'Malaysia',
        458: 'Malaysia',
        'MV': 'Maldives',
        'MDV': 'Maldives',
        '462': 'Maldives',
        462: 'Maldives',
        'ML': 'Mali',
        'MLI': 'Mali',
        '466': 'Mali',
        466: 'Mali',
        'MT': 'Malta',
        'MLT': 'Malta',
        '470': 'Malta',
        470: 'Malta',
        'MH': 'Marshall Islands',
        'MHL': 'Marshall Islands',
        '584': 'Marshall Islands',
        584: 'Marshall Islands',
        'MQ': 'Martinique',
        'MTQ': 'Martinique',
        '474': 'Martinique',
        474: 'Martinique',
        'MR': 'Mauritania',
        'MRT': 'Mauritania',
        '478': 'Mauritania',
        478: 'Mauritania',
        'MU': 'Mauritius',
        'MUS': 'Mauritius',
        '480': 'Mauritius',
        480: 'Mauritius',
        'YT': 'Mayotte',
        'MYT': 'Mayotte',
        '175': 'Mayotte',
        175: 'Mayotte',
        'MX': 'Mexico',
        'MEX': 'Mexico',
        '484': 'Mexico',
        484: 'Mexico',
        'FM': 'Micronesia, Federated States of',
        'FSM': 'Micronesia, Federated States of',
        '583': 'Micronesia, Federated States of',
        583: 'Micronesia, Federated States of',
        'MD': 'Moldova, Republic of',
        'MDA': 'Moldova, Republic of',
        '498': 'Moldova, Republic of',
        498: 'Moldova, Republic of',
        'MC': 'Monaco',
        'MCO': 'Monaco',
        '492': 'Monaco',
        492: 'Monaco',
        'MN': 'Mongolia',
        'MNG': 'Mongolia',
        '496': 'Mongolia',
        496: 'Mongolia',
        'ME': 'Montenegro',
        'MNE': 'Montenegro',
        '499': 'Montenegro',
        499: 'Montenegro',
        'MS': 'Montserrat',
        'MSR': 'Montserrat',
        '500': 'Montserrat',
        500: 'Montserrat',
        'MA': 'Morocco',
        'MAR': 'Morocco',
        '504': 'Morocco',
        504: 'Morocco',
        'MZ': 'Mozambique',
        'MOZ': 'Mozambique',
        '508': 'Mozambique',
        508: 'Mozambique',
        'MM': 'Myanmar',
        'MMR': 'Myanmar',
        '104': 'Myanmar',
        104: 'Myanmar',
        'NA': 'Namibia',
        'NAM': 'Namibia',
        '516': 'Namibia',
        516: 'Namibia',
        'NR': 'Nauru',
        'NRU': 'Nauru',
        '520': 'Nauru',
        520: 'Nauru',
        'NP': 'Nepal',
        'NPL': 'Nepal',
        '524': 'Nepal',
        524: 'Nepal',
        'NL': 'Netherlands, Kingdom of the',
        'NLD': 'Netherlands, Kingdom of the',
        '528': 'Netherlands, Kingdom of the',
        528: 'Netherlands, Kingdom of the',
        'NC': 'New Caledonia',
        'NCL': 'New Caledonia',
        '540': 'New Caledonia',
        540: 'New Caledonia',
        'NZ': 'New Zealand',
        'NZL': 'New Zealand',
        '554': 'New Zealand',
        554: 'New Zealand',
        'NI': 'Nicaragua',
        'NIC': 'Nicaragua',
        '558': 'Nicaragua',
        558: 'Nicaragua',
        'NE': 'Niger',
        'NER': 'Niger',
        '562': 'Niger',
        562: 'Niger',
        'NG': 'Nigeria',
        'NGA': 'Nigeria',
        '566': 'Nigeria',
        566: 'Nigeria',
        'NU': 'Niue',
        'NIU': 'Niue',
        '570': 'Niue',
        570: 'Niue',
        'NF': 'Norfolk Island',
        'NFK': 'Norfolk Island',
        '574': 'Norfolk Island',
        574: 'Norfolk Island',
        'MK': 'North Macedonia',
        'MKD': 'North Macedonia',
        '807': 'North Macedonia',
        807: 'North Macedonia',
        'MP': 'Northern Mariana Islands',
        'MNP': 'Northern Mariana Islands',
        '580': 'Northern Mariana Islands',
        580: 'Northern Mariana Islands',
        'NO': 'Norway',
        'NOR': 'Norway',
        '578': 'Norway',
        578: 'Norway',
        'OM': 'Oman',
        'OMN': 'Oman',
        '512': 'Oman',
        512: 'Oman',
        'PK': 'Pakistan',
        'PAK': 'Pakistan',
        '586': 'Pakistan',
        586: 'Pakistan',
        'PW': 'Palau',
        'PLW': 'Palau',
        '585': 'Palau',
        585: 'Palau',
        'PS': 'Palestine, State of',
        'PSE': 'Palestine, State of',
        '275': 'Palestine, State of',
        275: 'Palestine, State of',
        'PA': 'Panama',
        'PAN': 'Panama',
        '591': 'Panama',
        591: 'Panama',
        'PG': 'Papua New Guinea',
        'PNG': 'Papua New Guinea',
        '598': 'Papua New Guinea',
        598: 'Papua New Guinea',
        'PY': 'Paraguay',
        'PRY': 'Paraguay',
        '600': 'Paraguay',
        600: 'Paraguay',
        'PE': 'Peru',
        'PER': 'Peru',
        '604': 'Peru',
        604: 'Peru',
        'PH': 'Philippines',
        'PHL': 'Philippines',
        '608': 'Philippines',
        608: 'Philippines',
        'PN': 'Pitcairn',
        'PCN': 'Pitcairn',
        '612': 'Pitcairn',
        612: 'Pitcairn',
        'PL': 'Poland',
        'POL': 'Poland',
        '616': 'Poland',
        616: 'Poland',
        'PT': 'Portugal',
        'PRT': 'Portugal',
        '620': 'Portugal',
        620: 'Portugal',
        'PR': 'Puerto Rico',
        'PRI': 'Puerto Rico',
        '630': 'Puerto Rico',
        630: 'Puerto Rico',
        'QA': 'Qatar',
        'QAT': 'Qatar',
        '634': 'Qatar',
        634: 'Qatar',
        'RE': 'Réunion',
        'REU': 'Réunion',
        '638': 'Réunion',
        638: 'Réunion',
        'RO': 'Romania',
        'ROU': 'Romania',
        '642': 'Romania',
        642: 'Romania',
        'RU': 'Russian Federation',
        'RUS': 'Russian Federation',
        '643': 'Russian Federation',
        643: 'Russian Federation',
        'RW': 'Rwanda',
        'RWA': 'Rwanda',
        '646': 'Rwanda',
        646: 'Rwanda',
        'BL': 'Saint Barthélemy',
        'BLM': 'Saint Barthélemy',
        '652': 'Saint Barthélemy',
        652: 'Saint Barthélemy',
        'SH': 'Saint Helena, Ascension and Tristan da Cunha',
        'SHN': 'Saint Helena, Ascension and Tristan da Cunha',
        '654': 'Saint Helena, Ascension and Tristan da Cunha',
        654: 'Saint Helena, Ascension and Tristan da Cunha',
        'KN': 'Saint Kitts and Nevis',
        'KNA': 'Saint Kitts and Nevis',
        '659': 'Saint Kitts and Nevis',
        659: 'Saint Kitts and Nevis',
        'LC': 'Saint Lucia',
        'LCA': 'Saint Lucia',
        '662': 'Saint Lucia',
        662: 'Saint Lucia',
        'MF': 'Saint Martin (French part)',
        'MAF': 'Saint Martin (French part)',
        '663': 'Saint Martin (French part)',
        663: 'Saint Martin (French part)',
        'PM': 'Saint Pierre and Miquelon',
        'SPM': 'Saint Pierre and Miquelon',
        '666': 'Saint Pierre and Miquelon',
        666: 'Saint Pierre and Miquelon',
        'VC': 'Saint Vincent and the Grenadines',
        'VCT': 'Saint Vincent and the Grenadines',
        '670': 'Saint Vincent and the Grenadines',
        670: 'Saint Vincent and the Grenadines',
        'WS': 'Samoa',
        'WSM': 'Samoa',
        '882': 'Samoa',
        882: 'Samoa',
        'SM': 'San Marino',
        'SMR': 'San Marino',
        '674': 'San Marino',
        674: 'San Marino',
        'ST': 'Sao Tome and Principe',
        'STP': 'Sao Tome and Principe',
        '678': 'Sao Tome and Principe',
        678: 'Sao Tome and Principe',
        'SA': 'Saudi Arabia',
        'SAU': 'Saudi Arabia',
        '682': 'Saudi Arabia',
        682: 'Saudi Arabia',
        'SN': 'Senegal',
        'SEN': 'Senegal',
        '686': 'Senegal',
        686: 'Senegal',
        'RS': 'Serbia',
        'SRB': 'Serbia',
        '688': 'Serbia',
        688: 'Serbia',
        'SC': 'Seychelles',
        'SYC': 'Seychelles',
        '690': 'Seychelles',
        690: 'Seychelles',
        'SL': 'Sierra Leone',
        'SLE': 'Sierra Leone',
        '694': 'Sierra Leone',
        694: 'Sierra Leone',
        'SG': 'Singapore',
        'SGP': 'Singapore',
        '702': 'Singapore',
        702: 'Singapore',
        'SX': 'Sint Maarten (Dutch part)',
        'SXM': 'Sint Maarten (Dutch part)',
        '534': 'Sint Maarten (Dutch part)',
        534: 'Sint Maarten (Dutch part)',
        'SK': 'Slovakia',
        'SVK': 'Slovakia',
        '703': 'Slovakia',
        703: 'Slovakia',
        'SI': 'Slovenia',
        'SVN': 'Slovenia',
        '705': 'Slovenia',
        705: 'Slovenia',
        'SB': 'Solomon Islands',
        'SLB': 'Solomon Islands',
        '090': 'Solomon Islands',
        90: 'Solomon Islands',
        'SO': 'Somalia',
        'SOM': 'Somalia',
        '706': 'Somalia',
        706: 'Somalia',
        'ZA': 'South Africa',
        'ZAF': 'South Africa',
        '710': 'South Africa',
        710: 'South Africa',
        'GS': 'South Georgia and the South Sandwich Islands',
        'SGS': 'South Georgia and the South Sandwich Islands',
        '239': 'South Georgia and the South Sandwich Islands',
        239: 'South Georgia and the South Sandwich Islands',
        'SS': 'South Sudan',
        'SSD': 'South Sudan',
        '728': 'South Sudan',
        728: 'South Sudan',
        'ES': 'Spain',
        'ESP': 'Spain',
        '724': 'Spain',
        724: 'Spain',
        'LK': 'Sri Lanka',
        'LKA': 'Sri Lanka',
        '144': 'Sri Lanka',
        144: 'Sri Lanka',
        'SD': 'Sudan',
        'SDN': 'Sudan',
        '729': 'Sudan',
        729: 'Sudan',
        'SR': 'Suriname',
        'SUR': 'Suriname',
        '740': 'Suriname',
        740: 'Suriname',
        'SJ': 'Svalbard and Jan Mayen',
        'SJM': 'Svalbard and Jan Mayen',
        '744': 'Svalbard and Jan Mayen',
        744: 'Svalbard and Jan Mayen',
        'SE': 'Sweden',
        'SWE': 'Sweden',
        '752': 'Sweden',
        752: 'Sweden',
        'CH': 'Switzerland',
        'CHE': 'Switzerland',
        '756': 'Switzerland',
        756: 'Switzerland',
        'SY': 'Syrian Arab Republic',
        'SYR': 'Syrian Arab Republic',
        '760': 'Syrian Arab Republic',
        760: 'Syrian Arab Republic',
        'TW': 'Taiwan, Province of China',
        'TWN': 'Taiwan, Province of China',
        '158': 'Taiwan, Province of China',
        158: 'Taiwan, Province of China',
        'TJ': 'Tajikistan',
        'TJK': 'Tajikistan',
        '762': 'Tajikistan',
        762: 'Tajikistan',
        'TZ': 'Tanzania, United Republic of',
        'TZA': 'Tanzania, United Republic of',
        '834': 'Tanzania, United Republic of',
        834: 'Tanzania, United Republic of',
        'TH': 'Thailand',
        'THA': 'Thailand',
        '764': 'Thailand',
        764: 'Thailand',
        'TL': 'Timor-Leste',
        'TLS': 'Timor-Leste',
        '626': 'Timor-Leste',
        626: 'Timor-Leste',
        'TG': 'Togo',
        'TGO': 'Togo',
        '768': 'Togo',
        768: 'Togo',
        'TK': 'Tokelau',
        'TKL': 'Tokelau',
        '772': 'Tokelau',
        772: 'Tokelau',
        'TO': 'Tonga',
        'TON': 'Tonga',
        '776': 'Tonga',
        776: 'Tonga',
        'TT': 'Trinidad and Tobago',
        'TTO': 'Trinidad and Tobago',
        '780': 'Trinidad and Tobago',
        780: 'Trinidad and Tobago',
        'TN': 'Tunisia',
        'TUN': 'Tunisia',
        '788': 'Tunisia',
        788: 'Tunisia',
        'TR': 'Türkiye',
        'TUR': 'Türkiye',
        '792': 'Türkiye',
        792: 'Türkiye',
        'TM': 'Turkmenistan',
        'TKM': 'Turkmenistan',
        '795': 'Turkmenistan',
        795: 'Turkmenistan',
        'TC': 'Turks and Caicos Islands',
        'TCA': 'Turks and Caicos Islands',
        '796': 'Turks and Caicos Islands',
        796: 'Turks and Caicos Islands',
        'TV': 'Tuvalu',
        'TUV': 'Tuvalu',
        '798': 'Tuvalu',
        798: 'Tuvalu',
        'UG': 'Uganda',
        'UGA': 'Uganda',
        '800': 'Uganda',
        800: 'Uganda',
        'UA': 'Ukraine',
        'UKR': 'Ukraine',
        '804': 'Ukraine',
        804: 'Ukraine',
        'AE': 'United Arab Emirates',
        'ARE': 'United Arab Emirates',
        '784': 'United Arab Emirates',
        784: 'United Arab Emirates',
        'GB': 'United Kingdom of Great Britain and Northern Ireland',
        'GBR': 'United Kingdom of Great Britain and Northern Ireland',
        '826': 'United Kingdom of Great Britain and Northern Ireland',
        826: 'United Kingdom of Great Britain and Northern Ireland',
        'US': 'United States of America',
        'USA': 'United States of America',
        '840': 'United States of America',
        840: 'United States of America',
        'UM': 'United States Minor Outlying Islands',
        'UMI': 'United States Minor Outlying Islands',
        '581': 'United States Minor Outlying Islands',
        581: 'United States Minor Outlying Islands',
        'UY': 'Uruguay',
        'URY': 'Uruguay',
        '858': 'Uruguay',
        858: 'Uruguay',
        'UZ': 'Uzbekistan',
        'UZB': 'Uzbekistan',
        '860': 'Uzbekistan',
        860: 'Uzbekistan',
        'VU': 'Vanuatu',
        'VUT': 'Vanuatu',
        '548': 'Vanuatu',
        548: 'Vanuatu',
        'VE': 'Venezuela, Bolivarian Republic of',
        'VEN': 'Venezuela, Bolivarian Republic of',
        '862': 'Venezuela, Bolivarian Republic of',
        862: 'Venezuela, Bolivarian Republic of',
        'VN': 'Viet Nam',
        'VNM': 'Viet Nam',
        '704': 'Viet Nam',
        704: 'Viet Nam',
        'VG': 'Virgin Islands (British)',
        'VGB': 'Virgin Islands (British)',
        '092': 'Virgin Islands (British)',
        92: 'Virgin Islands (British)',
        'VI': 'Virgin Islands (U.S.)',
        'VIR': 'Virgin Islands (U.S.)',
        '850': 'Virgin Islands (U.S.)',
        850: 'Virgin Islands (U.S.)',
        'WF': 'Wallis and Futuna',
        'WLF': 'Wallis and Futuna',
        '876': 'Wallis and Futuna',
        876: 'Wallis and Futuna',
        'EH': 'Western Sahara',
        'ESH': 'Western Sahara',
        '732': 'Western Sahara',
        732: 'Western Sahara',
        'YE': 'Yemen',
        'YEM': 'Yemen',
        '887': 'Yemen',
        887: 'Yemen',
        'ZM': 'Zambia',
        'ZMB': 'Zambia',
        '894': 'Zambia',
        894: 'Zambia',
        'ZW': 'Zimbabwe',
        'ZWE': 'Zimbabwe',
        '716': 'Zimbabwe',
        716: 'Zimbabwe'
    }
    try:
        return codes[code]
    except KeyError:
        raise ValueError(f"Unknown country code '{code}'.")