from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    # Only check the volumes that are in scope for PCI
    if not IN_PCI_SCOPE(resource):
        return True

    return bool(resource["Encrypted"])
