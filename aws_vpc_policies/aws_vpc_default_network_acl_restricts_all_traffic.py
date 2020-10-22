from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error
from panther_oss_helpers import resource_lookup  # pylint: disable=import-error


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    default_id = 'arn:aws:ec2:' + resource['Region'] + ':' + resource[
        'AccountId'] + ':network-acl/' + resource['DefaultNetworkAclId']
    default_acl = resource_lookup(default_id)
    return not default_acl['Entries']
