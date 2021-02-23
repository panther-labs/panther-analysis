from panther_iocs import SUNBURST_IP_IOCS, ioc_match


def rule(event):
    return any(ioc_match(event.get("p_any_ip_addresses"), SUNBURST_IP_IOCS))


def title(event):
    ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), SUNBURST_IP_IOCS))
    return f"Sunburst Indicator of Compromise Detected [IPs]: {ips}"
