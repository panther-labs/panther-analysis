MAINTENANCE_WINDOW = 'sat:10:30-sat:11:00'


def policy(resource):
    return resource['PreferredMaintenanceWindow'] == MAINTENANCE_WINDOW
