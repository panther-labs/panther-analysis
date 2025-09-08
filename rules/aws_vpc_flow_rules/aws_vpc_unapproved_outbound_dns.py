from ipaddress import ip_network

from panther_aws_helpers import aws_rule_context

APPROVED_DNS_SERVERS = {
    "1.1.1.1",  # CloudFlare DNS
    "8.8.8.8",  # Google DNS
    # '10.0.0.1', # Internal DNS
}


def rule(event):
    # Common DNS ports, for better security use an application layer aware network monitor
    #
    # Defaults to True (no alert) if 'dstport' key is not present
    if event.udm("destination_port") != 53 and event.udm("destination_port") != 5353:
        return False

    # Only monitor traffic that is originating internally
    #
    # Defaults to True (no alert) if 'srcaddr' key is not present
    source_ip = event.udm("source_ip") or "0.0.0.0/32"
    if ip_network(source_ip).is_global:
        return False

    dest_ip = event.udm("destination_ip") or "192.168.0.1/32"
    if ip_network(dest_ip).is_private:
        return False

    # No clean way to default to False (no alert), so explicitly check for key
    return (
        bool(event.udm("destination_ip"))
        and event.udm("destination_ip") not in APPROVED_DNS_SERVERS
    )


def alert_context(event):
    return aws_rule_context(event)
