from ipaddress import ip_network

from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    # Only apply this policy if the Security Group is in scope for PCI
    if not IN_PCI_SCOPE(resource):
        return True

    for permission in resource["IpPermissionsEgress"] or []:
        # Check if any traffic can leave this security group to public IP space
        for ip_range in permission["IpRanges"] or []:
            if ip_range["CidrIp"] == "0.0.0.0/0" or not ip_network(ip_range["CidrIp"]).is_private:
                return False
        for ip_range in permission["Ipv6Ranges"] or []:
            if ip_range["CidrIpv6"] == "::/0" or not ip_network(ip_range["CidrIpv6"]).is_private:
                return False

    return True
