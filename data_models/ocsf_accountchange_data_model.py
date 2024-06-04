import json

from panther_base_helpers import deep_get


def source_ip_address(event):
    source_ip = deep_get(event, "src_endpoint", "ip") or deep_get(event, "src_endpoint", "domain")
    return source_ip


def request_parameters(event):
    request_parameters_str = deep_get(event, "api", "request", "data", default="{}")
    return json.loads(request_parameters_str)


def user_name(event):
    return request_parameters(event).get("userName", "")


def password_reset_required(event):
    return request_parameters(event).get("passwordResetRequired", "")
