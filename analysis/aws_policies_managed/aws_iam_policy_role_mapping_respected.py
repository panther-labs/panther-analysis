# This is a mapping of what policies must be attached to what roles in the account.
# The mapping is keyed by string policy names to tuples of role names. Ordering doesn't matter.
# Example:
# POLICY_ROLE_MAPPINGS = {
#   'ExamplePolicyName1': ('ExampleRoleName1', 'ExampleRoleName2', 'ExampleRoleName3'),
#   'ExamplePolicyName2': ('ExampleRoleName1', 'ExampleRoleName3', 'ExampleRoleName4'),
# }
POLICY_ROLE_MAPPINGS = {
    'TestPolicyName': ('TestRole1', 'TestRole2'),
}


def policy(resource):
    # Check if there are any required roles for this policy to be attached to
    if resource['PolicyName'] not in POLICY_ROLE_MAPPINGS:
        return True

    # Check if this policy is attached to any roles
    if resource['Entities']['PolicyRoles'] is None:
        return False

    # Build the list of role names this policy is actually attached to
    roles_attached = [
        role['RoleName'] for role in resource['Entities']['PolicyRoles']
    ]

    # For each required role, ensure that role has the policy attached
    for role_needed in POLICY_ROLE_MAPPINGS[resource['PolicyName']]:
        if role_needed not in roles_attached:
            return False
    return True
