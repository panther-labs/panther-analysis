def policy(resource):
    return resource['InlinePolicies'] is None and resource['ManagedPolicyNames'] is None
