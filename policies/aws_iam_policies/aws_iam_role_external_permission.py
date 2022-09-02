import json

from botocore.exceptions import NoCredentialsError
from panther_oss_helpers import BadLookup, resource_lookup

# This is a list of the account numbers included in the organization
# Example:
# accounts = [
#   '123456789012',
#   '123456789013'
# ]

# account *12 is used as an organizational account in built-in unit tests
# account *13 is used as a non-organizational account
accounts = [
    "123456789012",
]

# The specific permission that the policy checks
# CONFIGURATION_REQUIRED: replace default "lambda:AddPermission" in unit tests
#  with specified permission
PERMISSION = "lambda:AddPermission"

# CONFIGURATION_REQUIRED: modify policy to contain specified permission, above
mock_policy_has_permission = json.loads(
    """
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
"""
)

mock_policy_no_permission = json.loads(
    """
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
"""
)


# check to see if the account that is granted permission is third party
def check_account(resource):
    content_assumerole = resource.get("AssumeRolePolicyDocument")
    if isinstance(content_assumerole, str):
        content_assumerole = json.loads(content_assumerole)
    principal = content_assumerole["Statement"][0]["Principal"]
    if "AWS" in principal.keys():
        if isinstance(principal["AWS"], list):
            for principal_aws in principal["AWS"]:
                if not check_account_number(principal_aws):
                    return False
        else:
            return check_account_number(principal["AWS"])
    return True


def check_account_number(principal_aws):
    if principal_aws.split(":")[4] not in accounts:
        return False
    return True


def check_policy(policy_text):
    if isinstance(policy_text, str):
        policy_text = json.loads(policy_text)
    for statement in policy_text.get("Statement", []):
        if PERMISSION in statement.get("Action", []):
            return False
    return True


def policy(resource):
    # pylint: disable=too-complex
    if not check_account(resource):
        for policy_text in (resource.get("InlinePolicies") or {}).values():
            if not check_policy(policy_text):
                return False

        for managed_policy_name in resource.get("ManagedPolicyNames") or []:
            managed_policy_id = f"arn:aws:iam::{resource['AccountId']}:policy/{managed_policy_name}"
            try:
                # CONFIGURATION REQUIRED
                # to mock a Managed Policy
                #   - create mock policy, above
                #   - add '“IsUnitTest": true,' to test resource in .yml
                #   - add an additional 'key: value' pair and 'if/elif' block for each
                #     mocked case to .yml
                # Note: all Managed Policies in the test resource will be mocked
                # comment out 'if, else' block to optimize for production use
                if not resource.get("IsUnitTest"):
                    managed_policy = resource_lookup(managed_policy_id)
                else:
                    if resource.get("HasPermission"):
                        managed_policy = mock_policy_has_permission
                    elif resource.get("DoesNotHavePermission"):
                        managed_policy = mock_policy_no_permission
                    else:
                        return True
                # uncomment next line to optimize for production use
                # managed_policy = resource_lookup(managed_policy_id)
            except BadLookup:
                return True
            except NoCredentialsError:
                return True

            policy_text = managed_policy.get("PolicyDocument")
            if not check_policy(policy_text):
                return False

    return True
