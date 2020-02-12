from ipaddress import ip_network
APPROVED_DNS_SERVERS = {
    '1.1.1.1',  # CloudFlare DNS
    '8.8.8.8',  # Google DNS
    # '10.0.0.1', # Internal DNS
}


def rule(event):
    # This rule can only be evaluated if users have enabled these fields in their VPC Flow Logs
    if 'dstport' not in event or 'srcaddr' not in event or 'dstaddr' not in event:
        return False

    # Common DNS ports, for better security use an application layer aware network monitor
    if event['dstport'] != 53 and event['dstport'] != 5353:
        return False

    # Only monitor traffic that is originating internally
    if not ip_network(event['srcaddr']).is_private:
        return False

    return event['dstaddr'] not in APPROVED_DNS_SERVERS
