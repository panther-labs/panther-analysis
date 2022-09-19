from panther_iocs import LOG4J_IP_IOCS, ioc_match


def rule(event):
    return any(ioc_match(event.get("p_any_ip_addresses"), LOG4J_IP_IOCS))


def title(event):
    ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), LOG4J_IP_IOCS))
    return f"IP seen in LOG4J exploit scanning detected IP: {ips}"
