from panther_iocs import sunburst_sha256_ioc_match


def rule(event):
    return sunburst_sha256_ioc_match(event)


def title(event):
    return "Sunburst Indicator of Compromise (SHA-256) Detected"
