from ipaddress import ip_network
BUCKET_NAMES = {
    # Example bucket names go here
}
WHITELIST_NETWORKS = {
    # IP addresses (in CIDR notation) indicating approved IP ranges for accessing S3 buckets}
    ip_network('10.0.0.0/8'),
}


def rule(event):
    if BUCKET_NAMES:
        if event['bucket'] not in BUCKET_NAMES:
            return False

    if 'remoteIP' not in event:
        return False

    cidr_ip = ip_network(event['remoteIP'])
    return not any(
        cidr_ip.subnet_of(approved_ip_range)
        for approved_ip_range in WHITELIST_NETWORKS)


def dedup(event):
    return event.get('bucket')


def title(event):
    return 'Non-Approved IP access to S3 bucket {}'.format(event.get('bucket'))
