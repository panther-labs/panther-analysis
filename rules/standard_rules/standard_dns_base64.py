from panther_base_helpers import defang_ioc, is_base64

# Minimum length for Base64-encoded subdomain to be considered suspicious
# Legitimate service identifiers are typically shorter; exfil chunks are longer
MIN_BASE64_LENGTH = 28

# Known legitimate domains that use Base64-like subdomains for routing/load balancing
ALLOWED_DOMAINS = {
    "cloudapp.azure.com",
    "trafficmanager.net",
    "googleapis.com",
    "sharepoint.com",
    "cloudfront.net",
    "layerxsecurity.com",
    "office.com",  # Includes *.fp.measure.office.com telemetry
    "edge.microsoft.com",  # Includes cloudmessaging.edge.microsoft.com
}


def rule(event):
    query = event.udm("dns_query", default="")
    if not query:
        return False

    # Skip known legitimate enterprise services
    # Use proper domain suffix matching to prevent attacker bypass
    query_lower = query.lower().rstrip(".")  # Remove trailing dot if present
    for allowed_domain in ALLOWED_DOMAINS:
        # Match only if query ends with the allowed domain as a proper suffix
        # This prevents bypass via attacker-controlled domains like "cloudapp.azure.com.evil.com"
        if query_lower.endswith(f".{allowed_domain}") or query_lower == allowed_domain:
            return False

    args = query.split(".")

    # Check if Base64 encoded arguments are present in the DNS query
    for arg in args:
        # Skip short subdomains - focus on actual exfiltration chunks
        if len(arg) < MIN_BASE64_LENGTH:
            continue

        decoded = is_base64(arg)
        if decoded:
            return True

    return False


def title(event):
    defang_query = defang_ioc(event.udm("dns_query")) if event.udm("dns_query") else "no query"
    return f'Base64 encoded query detected from [{event.udm("source_ip")}], [{defang_query}]'


def alert_context(event):
    query = event.udm("dns_query", default="")

    # Recalculate decoded value for alert context (avoid global variable issues)
    decoded_part = ""
    if query:
        for arg in query.split("."):
            if len(arg) >= MIN_BASE64_LENGTH:
                decoded = is_base64(arg)
                if decoded:
                    decoded_part = decoded
                    break  # Use first decoded segment found

    context = {
        "source ip": event.udm("source_ip"),
        "defanged query": defang_ioc(query) if query else "no query",
        "decoded url part": decoded_part,
    }
    return context
