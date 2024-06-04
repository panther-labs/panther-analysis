import ipaddress
import json

from panther_base_helpers import deep_get


def load_ip_address(event):
    """
    This method ensures that either an IPv4 or IPv6 address is always returned.
    """
    source_ip = deep_get(event, "src_endpoint", "ip") or deep_get(event, "src_endpoint", "domain")
    if not source_ip:
        return None
    try:
        ipaddress.IPv4Address(source_ip)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(source_ip)
        except ipaddress.AddressValueError:
            return None
    return source_ip


def source_ip_address(event):
    source_ip = deep_get(event, "src_endpoint", "ip") or deep_get(event, "src_endpoint", "domain")
    return source_ip


def request_parameters(event):
    request_parameters_str = deep_get(event, "api", "request", "data", default="{}")
    return json.loads(request_parameters_str)


def policy_arn(event):
    return request_parameters(event).get("policyArn", "")


def user_name(event):
    return request_parameters(event).get("userName", "")
