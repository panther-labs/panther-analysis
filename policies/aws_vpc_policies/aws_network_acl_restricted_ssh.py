def policy(resource):
    for entry in resource["Entries"]:
        # Look for ingress rules from any IP.
        # This could be modified in the future to inspect the size
        # of the source network with the ipaddress.ip_network.num_addresses call.
        if (
            not entry["Egress"]
            and entry["CidrBlock"] == "0.0.0.0/0"
            and entry["RuleAction"] == "allow"
        ):
            # Check within a range of ports, normally the From/To would be set to 22,
            # but this covers the case where it could be 0-1024.
            if (
                "PortRange" not in entry
                or not entry["PortRange"]
                or entry["PortRange"]["From"] <= 22 <= entry["PortRange"]["To"]
            ):
                return False
    return True
