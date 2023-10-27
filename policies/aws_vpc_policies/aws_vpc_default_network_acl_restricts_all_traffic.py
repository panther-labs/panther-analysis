from panther_base_helpers import IN_PCI_SCOPE
from panther_oss_helpers import BadLookup, resource_lookup


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    # pylint: disable=line-too-long
    default_id = f"arn:aws:ec2:{resource['Region']}:{resource['AccountId']}:network-acl/{resource['DefaultNetworkAclId']}"
    try:
        default_acl = resource_lookup(default_id)
    except BadLookup:
        return True
    return not default_acl["Entries"]
