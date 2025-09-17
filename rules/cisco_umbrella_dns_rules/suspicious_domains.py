DOMAINS_TO_MONITOR = {"photoscape.ch", "malware-example.com"}  # Sample malware domains


def rule(event):
    return any(domain in event.get("domain") for domain in DOMAINS_TO_MONITOR)


def title(event):
    return "Suspicious lookup to domain " + event.get("domain", "<UNKNOWN_DOMAIN>")
