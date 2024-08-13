from panther_iocs import ioc_match

VOLEXITY_CONFLUENCE_IP_IOCS = []


def rule(_):
    return False  # any(ioc_match(event.get("p_any_ip_addresses"), VOLEXITY_CONFLUENCE_IP_IOCS))


def title(event):
    ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), VOLEXITY_CONFLUENCE_IP_IOCS))
    return f"IP seen from May 2022 exploitation of Confluence 0-Day: {ips}"
