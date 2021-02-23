from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error

# This is a generic policy that checks outbound permissions on Security Groups.
# You may wish to add additional logic specific to your use case.


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    if resource["IpPermissionsEgress"] is None:
        return True

    for permission in resource["IpPermissionsEgress"]:
        # Check if the permission is set to "All Ports"
        if permission["FromPort"] is None or permission["ToPort"] is None:
            return False
        # Check if the permission is set to "All TCP" or "All UDP" ports
        if permission["FromPort"] == 0 and permission["ToPort"] == 65535:
            return False

    return True
