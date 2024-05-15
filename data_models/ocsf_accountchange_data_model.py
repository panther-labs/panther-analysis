from panther_base_helpers import deep_get


def source_ip_address(event):
    source_ip = deep_get(event, "src_endpoint", "ip") or deep_get(event, "src_endpoint", "domain")
    return source_ip
