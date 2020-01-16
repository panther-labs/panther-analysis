from ipaddress import ip_network
APPROVED_PORTS = [
    80,
    443,
]


def rule(event):
    # Only monitor for non whitelisted ports
    if event['dstport'] in APPROVED_PORTS:
        return False

    # Only monitor for traffic coming from non-private IP space
    if ip_network(event['srcaddr']).is_private:
        return False

    # Alert if the traffic is destined for internal IP addresses
    if ip_network(event['dstaddr']).is_private:
        return True

    return False
