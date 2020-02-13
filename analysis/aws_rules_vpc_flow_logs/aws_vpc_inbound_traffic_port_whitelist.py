from ipaddress import ip_network
APPROVED_PORTS = {
    80,
    443,
}


def rule(event):
    # Can't perform this check without a destination port
    if 'dstport' not in event:
        return False

    # Only monitor for non whitelisted ports
    if event['dstport'] in APPROVED_PORTS:
        return False

    # Only monitor for traffic coming from non-private IP space
    #
    # Defaults to True (no alert) if 'srcaddr' key is not present
    if ip_network(event.get('srcaddr', '0.0.0.0/32')).is_private:
        return False

    # Alert if the traffic is destined for internal IP addresses
    #
    # Defaults to False (no alert) if 'dstaddr' key is not present
    return ip_network(event.get('dstaddr', '1.0.0.0/32')).is_private
