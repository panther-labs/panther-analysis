from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    for acl in resource['NetworkAcls']:
        if acl['IsDefault']:
            return not acl['Entries']
    return False
