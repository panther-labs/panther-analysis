from ipaddress import ip_network

from panther_aws_helpers import aws_rule_context

APPROVED_PORTS = {
    80,
    443,
}


def rule(event):
    # Can't perform this check without a destination port
    if not event.udm("destination_port"):
        return False

    # Only monitor for non allowlisted ports
    if event.udm("destination_port") in APPROVED_PORTS:
        return False

    # Only monitor for traffic coming from non-private IP space
    #
    # Defaults to True (no alert) if 'srcaddr' key is not present
    source_ip = event.udm("source_ip") or "0.0.0.0/32"
    if not ip_network(source_ip).is_global:
        return False

    # Alert if the traffic is destined for internal IP addresses
    #
    # Defaults to False (no alert) if 'dstaddr' key is not present
    destination_ip = event.udm("destination_ip") or "1.0.0.0/32"
    return not ip_network(destination_ip).is_global


def alert_context(event):
    return aws_rule_context(event)
