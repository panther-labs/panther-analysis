from ipaddress import ip_network
APPROVED_DNS_SERVERS = {
    '1.1.1.1',  # CloudFlare DNS
    '8.8.8.8',  # Google DNS
    # '10.0.0.1', # Internal DNS
}


def rule(event):
    # Common DNS ports, for better security use an application layer aware network monitor
    #
    # Defaults to True (no alert) if 'dstport' key is not present
    if event.get('dstport') != 53 and event.get('dstport') != 5353:
        return False

    # Only monitor traffic that is originating internally
    #
    # Defaults to True (no alert) if 'srcaddr' key is not present
    if not ip_network(event.get('srcaddr', '0.0.0.0/32')).is_private:
        return False

    # No clean way to check set memmbership and default to False (no alert), so explicitly check for key
    return 'dstaddr' in event && event['dstaddr'] not in APPROVED_DNS_SERVERS
