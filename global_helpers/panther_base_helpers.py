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

from dateutil import parser

# # # # # # # # # # # # # #
#       Exceptions        #
# # # # # # # # # # # # # #


class PantherUnexpectedAlert(Exception):
    """Error returned when a Panther detection encounters an unexpected situation."""


# # # # # # # # # # # # # #
#      Generic Helpers    #
# # # # # # # # # # # # # #

EMAIL_REGEX = re.compile(r"[\w.+%-]+@[\w.-]+\.[a-zA-Z]{2,}")


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


def is_ip_in_network(ip_addr, networks):
    """Check that a given IP is within a list of IP ranges"""
    return any(ip_address(ip_addr) in ip_network(network) for network in networks)


def pattern_match(string_to_match: str, pattern: str):
    """Wrapper around fnmatch for basic pattern globs"""
    return fnmatch(string_to_match, pattern)


def pattern_match_list(string_to_match: str, patterns: Sequence[str]):
    """Check that a string matches any pattern in a given list"""
    return any(fnmatch(string_to_match, p) for p in patterns)


def defang_ioc(ioc: str) -> str:
    """return defanged IOC from 1.1.1.1 to 1[.]1[.]1[.]1"""
    ioc = ioc.replace("http://", "hxxp://")
    ioc = ioc.replace("https://", "hxxps://")
    return ioc.replace(".", "[.]")


# IOC Helper functions:
def ioc_match(indicators: list, known_iocs: set) -> list:
    """Matches a set of indicators against known Indicators of Compromise

    :param indicators: List of potential indicators of compromise
    :param known_iocs: Set of known indicators of compromise
    :return: List of any indicator matches
    """
    # Check through the IP IOCs
    return [ioc for ioc in (indicators or []) if ioc in known_iocs]


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


def is_base64(b64: str, min_length: int = 28) -> str:
    # if the string is base64 encoded, return the decoded string
    # otherwise return an empty string
    # Minimum length for intentional base64 encoding
    # Legitimate service identifiers are typically shorter; exfil chunks are longer
    # Default 28 chars for DNS exfiltration, but can be customized per use case
    if len(b64) < min_length:
        return ""
    # Base64 strings should only contain ASCII characters
    try:
        b64.encode("ascii")
    except UnicodeEncodeError:
        return ""
    # Filter out hex strings (UUIDs without dashes) - these are common in CDN/service domains
    # 32-char hex strings like "ba680ec474b5402da89ce553c20075eb" decode to gibberish CJK
    if len(b64) == 32 and re.match(r"^[0-9a-fA-F]{32}$", b64):
        return ""
    # Base64 uses only: A-Z, a-z, 0-9, +, /, and = for padding
    if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", b64):
        return ""
    # Pad args with "=" to ensure proper decoding
    b64 = b64.ljust((len(b64) + 3) // 4 * 4, "=")
    # Decode and try multiple encodings
    try:
        decoded_bytes = b64decode(b64, validate=True)
    except (AsciiError, ValueError):
        return ""

    # Try decoding with different encodings in order of likelihood
    for encoding in ["ascii", "utf-16-le", "utf-8"]:
        try:
            decoded_str = decoded_bytes.decode(encoding)
            # Additional validation: check if decoded content is mostly printable
            # This filters out random alphanumeric strings that decode to gibberish
            if decoded_str:
                printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded_str) / len(
                    decoded_str
                )
                # Require at least 70% printable characters
                if printable_ratio < 0.7:
                    continue
            return decoded_str
        except UnicodeDecodeError:
            continue

    return ""


def key_value_list_to_dict(list_objects: List[dict], key: str, value: str) -> dict:
    # Convert a list of dictionaries to a single dictionary
    # example: [{'key': 'a', 'value': 1}, {'key': 'b', 'value': 2}]
    # becomes: {'a': 1, 'b': 2}
    return {item[key]: item[value] for item in list_objects}


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


# generate a PantherFlow investigation from an event
def pantherflow_investigation(event, interval="30m"):
    logtype = event.get("p_log_type", "").lower().replace(".", "_")
    timestamp = event.get("p_event_time", "")

    query = f"""union panther_signals.public.correlation_signals
    , panther_logs.public.{logtype}
| where p_event_time between time.parse_timestamp('{timestamp}') - time.parse_timespan('{interval}') .. time.parse_timestamp('{timestamp}') + time.parse_timespan('{interval}')
"""

    first = True
    for key, value in event.items():
        if key.startswith("p_any_") and key != "p_any_aws_account_ids":
            if first:
                query += f"| where arrays.overlap({key}, {value.copy()})\n"
                first = False
            else:
                query += f"     or arrays.overlap({key}, {value.copy()})\n"
    query += "| sort p_event_time"

    return query


def dbprint(*values: object, sep: str = " ", end: str = "\n"):  # pylint: disable=unused-argument
    """This is a placeholder function for printing to stdout when using pat debug. The debugging
    comamnd will patch this to `print`. We introduce this function so users can print potentially
    sensitive fields when debugging unit tests, and not worry about it being logged when Panther
    the rule on production logs."""
