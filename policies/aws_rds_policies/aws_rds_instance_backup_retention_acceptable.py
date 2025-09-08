MAX_RETENTION_DAYS = 180
MIN_RETENTION_DAYS = 7


def policy(resource):

    return MIN_RETENTION_DAYS <= resource["BackupRetentionPeriod"] <= MAX_RETENTION_DAYS
