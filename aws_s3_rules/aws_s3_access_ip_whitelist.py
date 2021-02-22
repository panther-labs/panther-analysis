from ipaddress import ip_network

BUCKETS_TO_MONITOR = {
    # Example bucket names to watch go here
}
WHITELIST_NETWORKS = {
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
    return not any(cidr_ip.subnet_of(approved_ip_range) for approved_ip_range in WHITELIST_NETWORKS)


def title(event):
    return "Non-Approved IP access to S3 Bucket [{}]".format(
        event.get("bucket", "<UNKNOWN_BUCKET>")
    )
