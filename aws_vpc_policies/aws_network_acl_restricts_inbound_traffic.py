# This is a generic policy for checking inbound rules on a Network ACL.
# It is recommended to add additional logic here based on your own use cases.
from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    for entry in resource['Entries']:
        if entry['RuleAction'] == 'allow' and not entry['Egress']:
            # Check if entry is set to "All Ports"
            if entry['PortRange'] is None:
                return False
    return True
