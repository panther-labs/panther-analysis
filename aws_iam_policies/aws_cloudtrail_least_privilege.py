CLOUDTRAIL_MANAGED_POLICY_ARN = 'arn:aws:iam::aws:policy/AWSCloudTrailFullAccess'
MAX_ADMIN_USERS = 2


def policy(resource):
    return (CLOUDTRAIL_MANAGED_POLICY_ARN in resource['ManagedPolicyARNs'] and
            len(resource['Users']) <= MAX_ADMIN_USERS)
