from ipaddress import ip_network
# This file exists to define global variables for use by other policies.

# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as DMZ space.
DMZ_NETWORKS = [
    ip_network('10.1.0.0/24'),
    ip_network('100.1.0.0/24'),
]


def is_dmz_cidr(ip_range):
    return any(ip_network(ip_range).overlaps(pci_network) for pci_network in PCI_NETWORKS)


DMZ_TAG_KEY = 'environment'
DMZ_TAG_VALUE = 'dmz'


# Defaults to False to assume something is not a DMZ if it is not tagged
def is_dmz_tags(resource):
    if resource['Tags'] is None:
        return False
    return resource['Tags'].get(DMZ_TAG_KEY) == DMZ_TAG_VALUE


# This policy is a no-op
def policy(_):
    return True
