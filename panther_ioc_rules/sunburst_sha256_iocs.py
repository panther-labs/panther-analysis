from panther_iocs import ioc_match, SUNBURST_SHA256_IOCS


def rule(event):
    return any(ioc_match(event.get('p_any_sha256_hashes'),
                         SUNBURST_SHA256_IOCS))


def title(event):
    # pylint: disable=line-too-long
    return f"Sunburst Indicator of Compromise Detected [SHA256 hash]: {','.join(ioc_match(event.get('p_any_sha256_hashes'), SUNBURST_SHA256_IOCS))}"
