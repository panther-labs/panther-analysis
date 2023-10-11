from panther_oss_helpers import BadLookup, resource_lookup


def policy(resource):
    # pylint: disable=line-too-long
    default_id = f"arn:aws:ec2:{resource['Region']}:{resource['AccountId']}:security-group/{resource['DefaultSecurityGroupId']}"
    try:
        default_sg = resource_lookup(default_id)
    except BadLookup:
        return True
    return default_sg["IpPermissions"] is None and default_sg["IpPermissionsEgress"] is None
