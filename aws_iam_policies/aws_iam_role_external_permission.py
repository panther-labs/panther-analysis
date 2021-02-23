import json
from panther_oss_helpers import resource_lookup

# This is a list of the account numbers included in the organization
# Example:
# accounts = [
#   '123456789012',
#   '123456789013'
# ]

# account *12 is used as an organizational account in built-in unit tests
# account *13 is used as a non-organizational account
accounts = [
    '123456789012',
]

# The specific permission that the policy checks
# CONFIGURATION_REQUIRED: replace default "lambda:AddPermission" in unit tests
#  with specified permission
PERMISSION = 'lambda:AddPermission'

# CONFIGURATION_REQUIRED: modify policy to contain specified permission, above
mock_policy_has_permission = json.loads('''
{
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:AddPermission",
                    "lambda:GetPolicy"
                ],
                "Resource": "*"
            }
        ]
    }
}
''')

mock_policy_no_permission = json.loads('''
{
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:ListAliases",
                "Resource": "*"
            }
        ]
    }
}
''')


# check to see if the account that is granted permission is third party
def check_account(resource):
    content_assumerole = resource.get('AssumeRolePolicyDocument')
    if isinstance(content_assumerole, str):
        content_assumerole = json.loads(content_assumerole)
    print('json loaded content_assumerole is:\n\n',
          json.dumps(content_assumerole, indent=2),
          '\n',
          sep='')
    principal = content_assumerole['Statement'][0]['Principal']
    print('Principal is', principal, '\n')
    if 'AWS' in principal.keys():
        print('There\'s an AWS trust principal\n')
        if isinstance(principal['AWS'], list):
            print('The AWS trust principal is a list (multiple principals)\n')
            for principal_aws in principal['AWS']:
                if not check_account_number(principal_aws):
                    return False
        else:
            print('The AWS trust principal is a string (single principal)\n')
            return check_account_number(principal['AWS'])
    else:
        print('There is no AWS trust principal (must be an AWS service)\n')
    return True


def check_account_number(principal_aws):
    print('principal_aws is', principal_aws, '\n')
    if principal_aws.split(':')[4] not in accounts:
        print('The account of the principal is not an internal account\n')
        return False
    print('The account of the principal is an internal account\n')
    return True


def check_policy(policy_text):
    if isinstance(policy_text, str):
        policy_text = json.loads(policy_text)
    for statement in policy_text.get('Statement', []):
        if PERMISSION in statement.get('Action', []):
            print('permission matches:', PERMISSION, '\n')
            print('Checking account...\n')
            return False
    return True


def policy(resource):
    print('\n----New Test Case----\n')
    for policy_text in (resource.get('InlinePolicies') or {}).values():
        print('Inline policy_text is', policy_text, '\n')
        if not check_policy(policy_text):
            if not check_account(resource):
                print('Result: Inline permission found for external account\n')
                return False
            print(
                'Result: Inline permission found for internal account or AWS service\n'
            )
        else:
            print('Result: Inline permission not found\n')

    for managed_policy_name in resource.get('ManagedPolicyNames') or []:
        managed_policy_id = f"arn:aws:iam::{resource['AccountId']}:policy/{managed_policy_name}"
        print('managed_policy_id is', managed_policy_id, '\n')
        try:
            # CONFIGURATION REQUIRED
            # to mock a Managed Policy
            #   - create mock policy, above
            #   - add '“IsUnitTest": true,' to test resource in .yml
            #   - add an additional 'key: value' pair and 'if/elif' block for each
            #     mocked case to .yml
            # Note: all Managed Policies in the test resource will be mocked
            # comment out 'if, else' block to optimize for production use
            if not resource.get('IsUnitTest'):
                managed_policy = resource_lookup(managed_policy_id)
            else:
                print("Running unit test for managed policy (mock lookup)\n")
                if resource.get('HasPermission'):
                    print("Using mock policy with specified permission\n")
                    managed_policy = mock_policy_has_permission
                elif resource.get('DoesNotHavePermission'):
                    print(
                        "Using mock policy without specified permission\n")
                    managed_policy = mock_policy_no_permission
                else:
                    print("Mock policy does not specify type (required)")
                    return True
            # uncomment next line to optimize for production use
            # managed_policy = resource_lookup(managed_policy_id)
        except:
            print('Managed policy does not exist or other lookup failure')
            return True

        policy_text = managed_policy.get('PolicyDocument')
        print('policy_text is', policy_text, '\n')
        if not check_policy(policy_text):
            if not check_account(resource):
                print('Permission found for external account\n')
                return False
            print('Permission found for internal account or AWS service\n')
        else:
            print('Permission not found\n')

    return True
