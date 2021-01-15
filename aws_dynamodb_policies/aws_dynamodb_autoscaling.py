from panther_base_helpers import deep_get

# If you do not wish to enforce application auto-scaling on your dynamo tables Global
# Secondary Indices, set this variable to False
CHECK_GSI = True


def policy(resource):
    # Check if this table has never had auto scaling configured
    if resource['BillingModeSummary'] is None and resource[
            'AutoScalingDescriptions'] is None:
        return False

    # Check if this table is not on provisioned billing (and therefore auto scaling does not apply)
    if resource['BillingModeSummary'] and resource['BillingModeSummary'][
            'BillingMode'] != 'PROVISIONED':
        return True

    # Check if application auto scaling is configured
    if resource['AutoScalingDescriptions'] is None:
        return False

    # Build a list of all the resources (the table and optionally the GSI's) to be checked
    table_id = 'table/' + resource['Name']
    resource_auto_scaling = {table_id: False}
    if CHECK_GSI:
        # We cannot use resource.get('GSI', []) here as the value is present, it is just a NoneType
        for gsi in deep_get(resource, 'GlobalSecondaryIndexes', default=[]):
            resource_auto_scaling[table_id + '/index/' +
                                  gsi['IndexName']] = False

    # Check that each resource that requires application autoscaling has it enabled
    for auto_scale_target in resource['AutoScalingDescriptions']:
        resource_auto_scaling[auto_scale_target['ResourceId']] = True

    # Return True if all resources have autoscaling enabled
    return all(resource_auto_scaling.values())
