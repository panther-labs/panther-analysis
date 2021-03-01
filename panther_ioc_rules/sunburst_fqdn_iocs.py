from panther_iocs import SUNBURST_FQDN_IOCS, ioc_match, sanitize_domain


def rule(event):
    return any(ioc_match(event.get("p_any_domain_names"), SUNBURST_FQDN_IOCS))


def title(event):
    domains = ",".join(ioc_match(event.get("p_any_domain_names"), SUNBURST_FQDN_IOCS))
    return sanitize_domain(f"Sunburst Indicator of Compromise Detected [Domains]: {domains}")
