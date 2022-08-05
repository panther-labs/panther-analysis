from panther_iocs import VOLEXITY_CONFLUENCE_IP_IOCS, ioc_match


def rule(event):
    return any(ioc_match(event.get("p_any_ip_addresses"), VOLEXITY_CONFLUENCE_IP_IOCS))


def title(event):
    ips = ",".join(ioc_match(event.get("p_any_ip_addresses"), VOLEXITY_CONFLUENCE_IP_IOCS))
    return f"IP seen from May 2022 exploitation of Confluence 0-Day: {ips}"
