RESTRICTED_PORTS = [22, 3389]


# Returns true if at least one of the ports in check_ports are between from_port and to_port
# Returns true if from_port or to_port is None as that indicates an unrestricted range of ports
def port_checker(check_ports, from_port, to_port):
    if from_port is None and to_port is None:
        return True

    for port in check_ports:
        if from_port <= port <= to_port:
            return True
    return False


def policy(resource):
    if resource["IpPermissions"] is None:
        return True

    for permission in resource["IpPermissions"]:
        src_open = False
        for ip_range in permission["IpRanges"] or []:
            if ip_range["CidrIp"] == "0.0.0.0/0":
                src_open = True
                break
        for ipv6_range in permission["Ipv6Ranges"] or []:
            if src_open or ipv6_range["CidrIpv6"] == "::/0":
                src_open = True
                break
        if src_open and port_checker(
            RESTRICTED_PORTS, permission["FromPort"], permission["ToPort"]
        ):
            return False
    return True
