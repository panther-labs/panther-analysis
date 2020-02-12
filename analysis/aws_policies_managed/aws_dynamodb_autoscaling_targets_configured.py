# If you do not wish to enforce application auto-scaling on your dynamo tables'
# Global Secondary Indices, set this variable to False
CHECK_GSI = True
READ_CAP = {
    "MIN": 5,
    "MAX": 15,
    "TYPE": "READ",
}
WRITE_CAP = {
    'MIN': 5,
    'MAX': 50000,
    "TYPE": "WRITE",
}


def policy(resource):
    # Check if this table has never had auto scaling configured
    if resource['BillingModeSummary'] is None and resource[
            'AutoScalingDescriptions'] is None:
        return False

    # Check if this table is not on provisioned billing (and therefore auto scaling does not apply)
    if resource['BillingModeSummary']['BillingMode'] != 'PROVISIONED':
        return True

    # Check if application auto scaling is configued at all
    if resource['AutoScalingDescriptions'] is None:
        return False

    # Build a list of all the resources (the table and optionally the GSI's) to be checked
    table_id = 'table/' + resource['Name']

    resource_auto_scaling = {
        table_id + '/READ': False,
        table_id + '/WRITE': False,
    }

    if CHECK_GSI:
        # We cannot use resource.get('GSI', []) here as the value is present, it is just a NoneType
        for gsi in resource['GlobalSecondaryIndexes'] or []:
            resource_auto_scaling[table_id + '/index/' + gsi['IndexName'] +
                                  '/READ'] = False
            resource_auto_scaling[table_id + '/index/' + gsi['IndexName'] +
                                  '/WRITE'] = False

    # Check that each resource that requires application autoscaling has it enabled
    for auto_scale_target in resource['AutoScalingDescriptions']:
        # Determine if this is a target for reading capacity or writing capacity
        cap = WRITE_CAP if 'WriteCapacityUnits' in auto_scale_target[
            'ScalableDimension'] else READ_CAP

        # Verify that the minimum and maximum scalable targets are within the configured bounds
        resource_auto_scaling[auto_scale_target['ResourceId'] + '/' +
                              cap['TYPE']] = (
                                  auto_scale_target['MinCapacity'] > cap['MIN']
                                  and
                                  auto_scale_target['MaxCapacity'] < cap['MAX'])

    # Verify that each scalable target was within configured bounds
    return all(resource_auto_scaling.values())
