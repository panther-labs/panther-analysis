# Retention period in days
MIN_RETENTION_DAYS = 3
MAX_RETENTION_DAYS = 90


def policy(resource):

    return MIN_RETENTION_DAYS <= resource["AutomatedSnapshotRetentionPeriod"] <= MAX_RETENTION_DAYS
