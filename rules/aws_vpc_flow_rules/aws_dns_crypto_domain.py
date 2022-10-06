from panther_iocs import CRYPTO_MINING_DOMAINS


def rule(event):
    query_name = event.get("query_name")
    for domain in CRYPTO_MINING_DOMAINS:
        if query_name.rstrip(".").endswith(domain):
            return True
    return False


def title(event):
    return (
        f"[{event.get('srcaddr')}:{event.get('srcport')}] "
        "made a DNS query for crypto mining domain: "
        f"[{event.get('query_name')}]."
    )


def dedup(event):
    return f"{event.get('srcaddr')}"
