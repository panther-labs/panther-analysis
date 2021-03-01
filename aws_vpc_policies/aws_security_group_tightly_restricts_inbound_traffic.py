from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error

MAX_PORTS_PER_PERMISSION = 10
RESTRICTED_PORTS = [
    21,  # FTP default
    22,  # SSH default
    23,  # Telnet default
    3389,  # RDP default
]


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    if resource["IpPermissions"] is None:
        return True

    for permission in resource["IpPermissions"]:
        # Check if the permission is set to "All Ports"
        if permission["FromPort"] is None or permission["ToPort"] is None:
            return False
        # Check if the permission allows too many ports. Alternatively, this can be modified to sum
        # open ports to have one running total.
        if permission["ToPort"] - permission["FromPort"] > MAX_PORTS_PER_PERMISSION:
            return False
        if any(permission["FromPort"] <= port <= permission["ToPort"] for port in RESTRICTED_PORTS):
            return False

    return True
