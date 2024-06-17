from panther_iocs import CRYPTO_MINING_DOMAINS


def rule(event):
    query_name = event.udm("dns_query")
    if not query_name:
        return False
    for domain in CRYPTO_MINING_DOMAINS:
        if query_name.rstrip(".").endswith(domain):
            return True
    return False


def title(event):
    return (
        f"[{event.udm('source_ip')}:{event.udm('source_port')}] "
        "made a DNS query for crypto mining domain: "
        f"[{event.udm('dns_query')}]."
    )


def dedup(event):
    return f"{event.udm('source_ip')}"
