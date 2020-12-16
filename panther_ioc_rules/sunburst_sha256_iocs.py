from panther_iocs import sunburst_sha256_ioc_match, intersection, SUNBURST_SHA256_IOCS


def rule(event):
    return sunburst_sha256_ioc_match(event)


def title(event):
    title_str = "Sunburst Indicator of Compromise Detected"
    if "p_any_sha256_hashes" in event:
        matches = intersection(event.get("p_any_sha256_hashes"),
                               SUNBURST_SHA256_IOCS)
        single_quote = '\''
        title_str += f" - {str(matches).replace(single_quote, '')}"
    return title_str
