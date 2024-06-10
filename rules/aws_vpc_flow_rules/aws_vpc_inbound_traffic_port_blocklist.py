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
    if event.udm("destination_port") not in CONTROLLED_PORTS:
        return False

    # Only monitor for traffic coming from non-private IP space
    #
    # Defaults to True (no alert) if 'srcaddr' key is not present
    source_ip = event.udm("source_ip") or "0.0.0.0/32"
    if not ip_network(source_ip).is_global:
        return False

    # Alert if the traffic is destined for internal IP addresses
    #
    # Defaults to False(no alert) if 'dstaddr' key is not present
    destination_ip = event.udm("destination_ip") or "1.0.0.0/32"
    return not ip_network(destination_ip).is_global


def alert_context(event):
    return aws_rule_context(event)
