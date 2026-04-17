# This is a generic policy for checking inbound rules on a Network ACL.
# It is recommended to add additional logic here based on your own use cases.


def policy(resource):

    for entry in resource["Entries"]:
        if entry["RuleAction"] == "allow" and not entry["Egress"]:
            # Check if entry is set to "All Ports"
            if entry["PortRange"] is None:
                return False
    return True
