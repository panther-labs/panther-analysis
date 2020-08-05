from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error
RETENTION_PERIOD_DAYS = 365


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    object_lock = resource['ObjectLockConfiguration']

    # Object lock configuration is not enabled, or enabled without a rule
    if not object_lock or object_lock[
            'ObjectLockEnabled'] != 'Enabled' or not object_lock['Rule']:
        return False

    # Ensure ObjectLockConfiguration is in COMPLIANCE mode, not GOVERNANCE mode
    if object_lock['Rule']['DefaultRetention']['Mode'] != 'COMPLIANCE':
        return False

    return object_lock['Rule']['DefaultRetention'][
        'Days'] >= RETENTION_PERIOD_DAYS
