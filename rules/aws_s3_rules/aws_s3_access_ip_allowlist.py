from ipaddress import IPv4Network, IPv6Network, ip_network

from panther_aws_helpers import aws_rule_context

BUCKETS_TO_MONITOR = {
    # Example bucket names to watch go here
}
ALLOWLIST_NETWORKS = {
    # IP addresses (in CIDR notation) indicating approved IP ranges for accessing S3 buckets}
    ip_network("10.0.0.0/8"),
}


def rule(event):
    if BUCKETS_TO_MONITOR:
        if event.get("bucket") not in BUCKETS_TO_MONITOR:
            return False

    if "remoteip" not in event:
        return False

    cidr_ip = ip_network(event.get("remoteip"))
    return not any(
        is_subnet(approved_ip_range, cidr_ip) for approved_ip_range in ALLOWLIST_NETWORKS
    )


def title(event):
    return f"Non-Approved IP access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"


def alert_context(event):
    return aws_rule_context(event)


def is_subnet(supernet: IPv4Network | IPv6Network, subnet: IPv4Network | IPv6Network) -> bool:
    """Return true if 'subnet' is a subnet of 'supernet'"""
    # We can't do a classic subnet comparison between v4 and v6 networks, so we have to explictly
    #   check for version mismatch first
    if supernet.network_address.version != subnet.network_address.version:
        return False
    # Else, do the subnet calculation
    return subnet.subnet_of(supernet)
