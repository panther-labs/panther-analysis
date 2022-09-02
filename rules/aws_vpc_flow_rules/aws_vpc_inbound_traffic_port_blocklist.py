from ipaddress import ip_network

from panther_base_helpers import aws_rule_context

CONTROLLED_PORTS = {
    22,
    3389,
}


def rule(event):
    # Only monitor for blocklisted ports
    #
    # Defaults to True (no alert) if 'dstport' is not present
    if event.get("dstport") not in CONTROLLED_PORTS:
        return False

    # Only monitor for traffic coming from non-private IP space
    #
    # Defaults to True (no alert) if 'srcaddr' key is not present
    if ip_network(event.get("srcaddr", "0.0.0.0/32")).is_private:
        return False

    # Alert if the traffic is destined for internal IP addresses
    #
    # Defaults to False(no alert) if 'dstaddr' key is not present
    return ip_network(event.get("dstaddr", "1.0.0.0/32")).is_private


def alert_context(event):
    return aws_rule_context(event)
