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

# # # # # # # # # # # # # #
#       Exceptions        #
# # # # # # # # # # # # # #


class PantherUnexpectedAlert(Exception):
    """Error returned when a Panther detection encounters an unexpected situation."""


# # # # # # # # # # # # # #
#      Generic Helpers    #
# # # # # # # # # # # # # #


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
        event.deep_get(field_name)
        or event.deep_get("event", field_name)
        or event.deep_get("unknown_payload", field_name)
        or default
    )


def slack_alert_context(event):
    return {
        "actor-name": event.deep_get("actor", "user", "name", default="<MISSING_NAME>"),
        "actor-email": event.deep_get("actor", "user", "email", default="<MISSING_EMAIL>"),
        "actor-ip": event.deep_get("context", "ip_address", default="<MISSING_IP>"),
        "user-agent": event.deep_get("context", "ua", default="<MISSING_UA>"),
    }


def github_alert_context(event):
    return {
        "action": event.get("action", ""),
        "actor": event.get("actor", ""),
        "actor_location": event.deep_get("actor_location", "country_code"),
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


def eks_panther_obj_ref(event):
    user = event.deep_get("user", "username", default="<NO_USERNAME>")
    source_ips = event.get("sourceIPs", ["0.0.0.0"])  # nosec
    verb = event.get("verb", "<NO_VERB>")
    obj_name = event.deep_get("objectRef", "name", default="<NO_OBJECT_NAME>")
    obj_ns = event.deep_get("objectRef", "namespace", default="<NO_OBJECT_NAMESPACE>")
    obj_res = event.deep_get("objectRef", "resource", default="<NO_OBJECT_RESOURCE>")
    obj_subres = event.deep_get("objectRef", "subresource", default="")
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
