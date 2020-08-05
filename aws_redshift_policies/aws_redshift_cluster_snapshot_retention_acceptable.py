from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error
# Retention period in days
MIN_RETENTION_DAYS = 3
MAX_RETENTION_DAYS = 90


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    return MIN_RETENTION_DAYS <= resource[
        'AutomatedSnapshotRetentionPeriod'] <= MAX_RETENTION_DAYS
