"""
Here, default values for `panther_config.config` are defined
"""

from ipaddress import ip_network

# A list of public DNS domain names that fall under the administrative domain of
# the Panther installation
ORGANIZATION_DOMAINS = ["example.com"]

AWS_ACCOUNTS = {
    # Add your AWS account IDs/names below:
    "123456789012": "sample-account",
}
DROPBOX_ALLOWED_SHARE_DOMAINS = ORGANIZATION_DOMAINS
DROPBOX_TRUSTED_OWNERSHIP_DOMAINS = ORGANIZATION_DOMAINS
GCP_PRODUCTION_PROJECT_IDS = ["example-production", "example-platform"]
GCP_ORG_ID = "888888888888"
GSUITE_TRUSTED_FORWARDING_DESTINATION_DOMAINS = ORGANIZATION_DOMAINS
GSUITE_TRUSTED_OWNERSHIP_DOMAINS = ORGANIZATION_DOMAINS
MS_EXCHANGE_ALLOWED_FORWARDING_DESTINATION_DOMAINS = ORGANIZATION_DOMAINS
MS_EXCHANGE_ALLOWED_FORWARDING_DESTINATION_EMAILS = ["postmaster@" + ORGANIZATION_DOMAINS[0]]
TELEPORT_ORGANIZATION_DOMAINS = ORGANIZATION_DOMAINS

# Expects a map with a Key 'Tags' that maps to a map of key/value string pairs, or None if no
# tags are present.
# All Panther defined resources meet this requirement.
CDE_TAG_KEY = "environment"
CDE_TAG_VALUE = "pci"


DMZ_NETWORKS = [
    # ip_network("10.1.0.0/24"),
]

DMZ_TAGS = set(
    [
        ("environment", "dmz"),
    ]
)


PCI_NETWORKS = [
    # ip_network("10.0.0.0/24"),
]


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as DMZ space.
def is_dmz_cidr(ip_range):
    """This function determines whether a given IP range is within the defined DMZ IP range."""
    return any(ip_network(ip_range).overlaps(dmz_network) for dmz_network in DMZ_NETWORKS)


# Defaults to False to assume something is not a DMZ if it is not tagged
def is_dmz_tags(resource, dmz_tags):
    """This function determines whether a given resource is tagged as existing in a DMZ."""
    if resource["Tags"] is None:
        return False
    for key, value in dmz_tags:
        if resource["Tags"].get(key) == value:
            return True
    return False


# Expects a string in cidr notation (e.g. '10.0.0.0/24') indicating the ip range being checked
# Returns True if any ip in the range is marked as in scope
def is_pci_scope_cidr(ip_range):
    return any(ip_network(ip_range).overlaps(pci_network) for pci_network in PCI_NETWORKS)


# Defaults to True to assume something is in scope if it is not tagged
def in_pci_scope_tags(resource):
    if resource.get("Tags") is None:
        return True
    return resource["Tags"].get(CDE_TAG_KEY) == CDE_TAG_VALUE


# Function variables here so that implementation details of these functions can be changed without
# having to rename the function in all locations its used, or having an outdated name on the actual
# function being used, etc.
IN_PCI_SCOPE = in_pci_scope_tags
