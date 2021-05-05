# IAM policy ARN's list in this variable will be checked against the policies assigned to all IAM
# resources (users, groups, roles) and this rule will fail if any policy ARN in the blacklist is
# assigned to a user
IAM_POLICY_ARN_BLACKLIST = [
    "TEST_BLACKLISTED_ARN",
]


def policy(resource):
    # Check if the IAM resource has any managed policies
    if resource["ManagedPolicyNames"] is None:
        return True

    # Iterate through the blacklist and return true if the resource is in violation
    for iam_policy in IAM_POLICY_ARN_BLACKLIST:
        if iam_policy in resource["ManagedPolicyNames"]:
            return False

    return True
