MIN_DAYS_TO_RETAIN_LOGS = 365


def policy(resource):
    retention_in_days = resource['RetentionInDays']
    # If retention is None, logs will never expire.
    return retention_in_days is None or retention_in_days >= MIN_DAYS_TO_RETAIN_LOGS
