DOMAINS_TO_MONITOR = {
    'photoscape.ch'  # Sample malware domain
}


def rule(event):
    return any(domain in event['domain'] for domain in DOMAINS_TO_MONITOR)


def dedup(event):
    return event['domain']


def title(event):
    return 'Suspicious lookup to domain ' + event['domain']
