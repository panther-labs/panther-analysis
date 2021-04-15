from panther_base_helpers import deep_get

MAX_RETENTION_PERIOD = 365
MIN_RETENTION_PERIOD = 90


def policy(resource):
    if resource.get("LifecycleRules") is None:
        return False

    for lifecycle_rule in resource.get("LifecycleRules", []):
        if lifecycle_rule.get("Expiration") is None or lifecycle_rule.get("Status") != "Enabled":
            continue

        rule_retention_period_days = deep_get(lifecycle_rule, "Expiration", "Days", default=0)

        if rule_retention_period_days is None:
            continue

        if MIN_RETENTION_PERIOD <= rule_retention_period_days <= MAX_RETENTION_PERIOD:
            return True

    return False
