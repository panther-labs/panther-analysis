from ipaddress import ip_network
CONTROLLED_PORTS = [
    22,
    3389,
]


def rule(event):
    # Only monitor for blacklisted ports
    if event['dstport'] not in CONTROLLED_PORTS:
        return False

    # Only monitor for traffic coming from non-private IP space
    if ip_network(event['srcaddr']).is_private:
        return False

    # Alert if the traffic is destined for internal IP addresses
    if ip_network(event['dstaddr']).is_private:
        return True

    return False
