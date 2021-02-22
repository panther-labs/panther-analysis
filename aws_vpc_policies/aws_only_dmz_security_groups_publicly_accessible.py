from ipaddress import ip_network
from panther_base_helpers import IS_DMZ  # pylint: disable=import-error


def policy(resource):
    # If this security group allows no inbound connections, it is secure
    if resource["IpPermissions"] is None:
        return True

    # DMZ security groups can have inbound permissions from the internet
    if IS_DMZ(resource):
        return True

    for permission in resource["IpPermissions"]:
        # Check if any traffic is allowed from public IP space
        for ip_range in permission["IpRanges"] or []:
            if ip_range["CidrIp"] == "0.0.0.0/0" or not ip_network(ip_range["CidrIp"]).is_private:
                return False
        for ip_range in permission["Ipv6Ranges"] or []:
            if ip_range["CidrIpv6"] == "::/0" or not ip_network(ip_range["CidrIpv6"]).is_private:
                return False

    return True
