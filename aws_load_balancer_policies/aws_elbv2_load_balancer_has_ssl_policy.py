from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    # Casting to Bool as this may be None and we cannot return a NoneType
    return bool(resource['SSLPolicies'])
