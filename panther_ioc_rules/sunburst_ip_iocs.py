from panther_iocs import sunburst_ip_ioc_match


def rule(event):
    return sunburst_ip_ioc_match(event)


def title(event):
    return "Sunburst Indicator of Compromise (IP) Detected"
