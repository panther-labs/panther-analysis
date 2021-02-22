from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error

# This is generic policy that checks outbound traffic rules on a Network ACL.
# It is recommended you add additional logic for your own use cases.


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    for entry in resource["Entries"]:
        if entry["RuleAction"] == "allow" and entry["Egress"]:
            # Check if entry is set to "All Ports"
            if entry["PortRange"] is None:
                return False
    return True
