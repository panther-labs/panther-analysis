import json
from ipaddress import ip_network
from unittest.mock import MagicMock

from panther_base_helpers import is_dmz_tags
from panther_config import config

DMZ_TAGS = config.DMZ_TAGS


def policy(resource):
    # If this security group allows no inbound connections, it is secure
    if resource["IpPermissions"] is None:
        return True

    # DMZ security groups can have inbound permissions from the internet
    global DMZ_TAGS  # pylint: disable=global-statement
    if isinstance(DMZ_TAGS, MagicMock):
        DMZ_TAGS = {tuple(kv) for kv in json.loads(DMZ_TAGS())}
    if is_dmz_tags(resource, DMZ_TAGS):
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
