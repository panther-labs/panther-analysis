# This is a generic policy that checks inbound permissions on a Security Group.
# You may wish to add additional logic specific to your use cases.


def policy(resource):

    if resource["IpPermissions"] is None:
        return True

    for permission in resource["IpPermissions"]:
        # Check if the permission is set to "All Ports"
        if permission["FromPort"] is None or permission["ToPort"] is None:
            return False
        # Check if the permission is set to "All TCP" or "All UDP" ports
        if permission["FromPort"] == 0 and permission["ToPort"] == 65535:
            return False

    return True
