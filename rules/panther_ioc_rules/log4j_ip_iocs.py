from panther_iocs import ioc_match

LOG4J_IP_IOCS = []


def rule(_):
    return False  # any(ioc_match(event.get("p_any_ip_addresses"), LOG4J_IP_IOCS))


def title(event):
    ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), LOG4J_IP_IOCS))
    return f"IP seen in LOG4J exploit scanning detected IP: {ips}"
