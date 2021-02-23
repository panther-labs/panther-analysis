from panther_oss_helpers import resource_lookup  # pylint: disable=import-error


def policy(resource):
    # pylint: disable=line-too-long
    default_id = f"arn:aws:ec2:{resource['Region']}:{resource['AccountId']}:security-group/{resource['DefaultSecurityGroupId']}"
    default_sg = resource_lookup(default_id)
    return default_sg["IpPermissions"] is None and default_sg["IpPermissionsEgress"] is None
