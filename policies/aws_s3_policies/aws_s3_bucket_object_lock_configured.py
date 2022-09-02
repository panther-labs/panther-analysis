from panther_base_helpers import IN_PCI_SCOPE, deep_get

RETENTION_PERIOD_DAYS = 365


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    object_lock = resource["ObjectLockConfiguration"]

    # Object lock configuration is not enabled, or enabled without a rule
    if not object_lock or object_lock["ObjectLockEnabled"] != "Enabled" or not object_lock["Rule"]:
        return False

    # Ensure ObjectLockConfiguration is in COMPLIANCE mode, not GOVERNANCE mode
    if deep_get(object_lock, "Rule", "DefaultRetention", "Mode") != "COMPLIANCE":
        return False

    return (
        deep_get(object_lock, "Rule", "DefaultRetention", "Days", default=0)
        >= RETENTION_PERIOD_DAYS
    )
