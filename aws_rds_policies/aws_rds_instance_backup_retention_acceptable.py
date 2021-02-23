from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error

MAX_RETENTION_DAYS = 180
MIN_RETENTION_DAYS = 7


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    return MIN_RETENTION_DAYS <= resource["BackupRetentionPeriod"] <= MAX_RETENTION_DAYS
