from panther_base_helpers import IN_PCI_SCOPE


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    if resource["IpPermissions"] is None:
        return True

    for permission in resource["IpPermissions"]:
        # Only check Security Group -> Security Group permissions
        if not permission["UserIdGroupPairs"]:
            continue
        # Check if the permission is set to "All Ports"
        if permission["FromPort"] is None or permission["ToPort"] is None:
            return False
        # Check if the permission is set to "All TCP" or "All UDP" ports
        if permission["FromPort"] == 0 and permission["ToPort"] == 65535:
            return False

    return True
