from panther_iocs import sunburst_fqdn_ioc_match


def rule(event):
    return sunburst_fqdn_ioc_match(event)


def title(event):
    return "Sunburst Indicator of Compromise (FQDN) Detected"
