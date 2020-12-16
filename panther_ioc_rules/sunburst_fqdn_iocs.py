from panther_iocs import sunburst_fqdn_ioc_match, intersection, SUNBURST_FQDN_IOCS


def rule(event):
    return sunburst_fqdn_ioc_match(event)


def title(event):
    title_str = "Sunburst Indicator of Compromise Detected"
    if "p_any_domain_names" in event:
        matches = intersection(event.get("p_any_domain_names"),
                               SUNBURST_FQDN_IOCS)
        single_quote = '\''
        title_str += f" - {str(matches).replace('.', '[.]').replace(single_quote, '')}"
    return title_str
