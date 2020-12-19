import json
from panther_oss_helpers import resource_lookup

# This is a list of the account numbers included in the organization
# Example:
# accounts = [
#   '123456789012',
#   '123456789013'
# ]
accounts = [
    '123456789012'
    ]

# this is the specific permission that the policy checks
permission_check = 'lambda:AddPermission'

def check_account(resource):
    content_assumerole = resource['AssumeRolePolicyDocument']
    principal = content_assumerole['Statement'][0]['Principal']

    if 'AWS' in principal.keys():
        if type(principal['AWS']) is list:
            for principal_aws in principal['AWS']:
                if principal_aws.split(':')[4] not in accounts:
                    return False
        else:
            if principal['AWS'].split(':')[4] not in accounts:
                return False
                
    return True


def policy(resource):
    content_inline = resource['InlinePolicies']

    for policy in content_inline:
        policy_text = json.loads(content_inline[policy])
        permissions = policy_text['Statement'][0]['Action']

        if permission_check in permissions:
            return check_account(resource)

    for managed_policy_name in resource['ManagedPolicyNames']:
        managed_policy_id = f"arn:aws:iam::{resource['AccountId']}:policy/{managed_policy_name}"
        managed_policy = resource_lookup(managed_policy_id)
        policy_text = json.loads(managed_policy['PolicyDocument'])
        permissions = policy_text['Statement'][0]['Action']
        
        if permission_check in permissions:
            return check_account(resource)

    return True
