from panther_iocs import sunburst_ip_ioc_match, intersection, SUNBURST_IP_IOCS


def rule(event):
    return sunburst_ip_ioc_match(event)


def title(event):
    title_str = "Sunburst Indicator of Compromise Detected"
    if "p_any_ip_addresses" in event:
        matches = intersection(event.get("p_any_ip_addresses"), SUNBURST_IP_IOCS)
        single_quote = '\''
        title_str += f" - {str(matches).replace('.', '[.]').replace(single_quote, '')}"
    return title_str
