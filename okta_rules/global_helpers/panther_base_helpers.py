from ipaddress import ip_network
# This file exists to define global variables for use by other policies.

# Expects a map with the a Key 'Tags' that maps to a map of key/value string pairs, or None if no
# tags are present.
# All Panther defined resources meet this requirement.
CDE_TAG_KEY = 'environment'
CDE_TAG_VALUE = 'pci'


# Defaults to True to assume something is in scope if it is not tagged
def in_pci_scope_tags(resource):
    if resource.get('Tags') is None:
        return True
    return resource['Tags'].get(CDE_TAG_KEY) == CDE_TAG_VALUE


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as in scope
PCI_NETWORKS = [
    ip_network('10.0.0.0/24'),
]


def in_pci_scope_cidr(ip_range):
    return any(
        ip_network(ip_range).overlaps(pci_network)
        for pci_network in PCI_NETWORKS)


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as DMZ space.
DMZ_NETWORKS = [
    ip_network('10.1.0.0/24'),
    ip_network('100.1.0.0/24'),
]


def is_dmz_cidr(ip_range):
    return any(
        ip_network(ip_range).overlaps(pci_network)
        for pci_network in PCI_NETWORKS)


DMZ_TAG_KEY = 'environment'
DMZ_TAG_VALUE = 'dmz'


# Defaults to False to assume something is not a DMZ if it is not tagged
def is_dmz_tags(resource):
    if resource['Tags'] is None:
        return False
    return resource['Tags'].get(DMZ_TAG_KEY) == DMZ_TAG_VALUE


# Function variables here so that implementation details of these functions can be changed without
# having to rename the function in all locations its used, or having an outdated name on the actual
# function being used, etc.
IN_PCI_SCOPE = in_pci_scope_tags
IS_DMZ = is_dmz_tags


# This policy is a no-op
def policy(_):
    return True
