from panther_iocs import SUNBURST_SHA256_IOCS, ioc_match


def rule(event):
    return any(ioc_match(event.get("p_any_sha256_hashes"), SUNBURST_SHA256_IOCS))


def title(event):
    hashes = ",".join(ioc_match(event.get("p_any_sha256_hashes"), SUNBURST_SHA256_IOCS))
    return f"Sunburst Indicator of Compromise Detected [SHA256 hash]: {hashes}"
