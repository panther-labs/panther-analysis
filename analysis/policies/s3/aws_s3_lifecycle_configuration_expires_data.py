MAX_RETENTION_PERIOD = 365
MIN_RETENTION_PERIOD = 90


def policy(resource):
    if resource['LifecycleRules'] is None:
        return False

    for lifecycle_rule in resource['LifecycleRules']:
        if lifecycle_rule['Expiration'] is None or lifecycle_rule['Status'] != 'Enabled':
            continue
        if MIN_RETENTION_PERIOD < lifecycle_rule['Expiration']['Days'] < MAX_RETENTION_PERIOD:
            return True

    return False
