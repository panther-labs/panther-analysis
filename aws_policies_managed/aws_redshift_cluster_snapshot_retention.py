# Retention period in days
RETENTION_PERIOD = 3


def policy(resource):
    return resource['AutomatedSnapshotRetentionPeriod'] >= RETENTION_PERIOD
