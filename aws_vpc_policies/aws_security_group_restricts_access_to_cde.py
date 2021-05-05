from ipaddress import ip_network

from panther_base_helpers import IN_PCI_SCOPE


def policy(resource):
    # Only apply this policy to security groups in scope for PCI
    if not IN_PCI_SCOPE(resource):
        return True

    for permission in resource["IpPermissions"] or []:
        # Check if any traffic is allowed from public IP space
        for ip_range in permission["IpRanges"] or []:
            if ip_range["CidrIp"] == "0.0.0.0/0" or not ip_network(ip_range["CidrIp"]).is_private:
                return False
        for ip_range in permission["Ipv6Ranges"] or []:
            if ip_range["CidrIpv6"] == "::/0" or not ip_network(ip_range["CidrIpv6"]).is_private:
                return False

    return True
