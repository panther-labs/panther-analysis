from panther_iocs import ioc_match, SUNBURST_FQDN_IOCS, sanitize_domain


def rule(event):
    return any(ioc_match(event.get('p_any_domain_names'), SUNBURST_FQDN_IOCS))


def title(event):
    # pylint: disable=line-too-long
    return sanitize_domain(
        f"Sunburst Indicator of Compromise Detected [Domains]: {','.join(ioc_match(event.get('p_any_domain_names'), SUNBURST_FQDN_IOCS))}"
    )
