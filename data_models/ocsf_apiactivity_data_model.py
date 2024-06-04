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


def project_visibility(event):
    return request_parameters(event).get("projectVisibility", "")


def attribute_name(event):
    return request_parameters(event).get("attributeName", "")


def values_to_add(event):
    return request_parameters(event).get("valuesToAdd", "")


def policy_name(event):
    return request_parameters(event).get("policyName", "")


def cidr_block(event):
    return request_parameters(event).get("cidrBlock", "")


def rule_action(event):
    return request_parameters(event).get("ruleAction", "")


def egress(event):
    return request_parameters(event).get("egress", "")


def request_enable(event):
    return request_parameters(event).get("enable", "")


def resource_arn(event):
    return request_parameters(event).get("resourceArn", "")
