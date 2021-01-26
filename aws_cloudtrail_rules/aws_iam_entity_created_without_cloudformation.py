import re
from panther_base_helpers import deep_get

# The role dedicated for IAM administration
IAM_ADMIN_ROLES = {
    'arn:aws:iam::123456789012:role/IdentityCFNServiceRole',
}

# The role patterns dedicated for IAM Service Roles
IAM_ADMIN_ROLE_PATTERNS = {'arn:aws:iam::[0-9]+:role/IdentityCFNServiceRole'}

# API calls that are indicative of IAM entity creation
IAM_ENTITY_CREATION_EVENTS = {
    'BatchCreateUser',
    'CreateGroup',
    'CreateInstanceProfile',
    'CreatePolicy',
    'CreatePolicyVersion',
    'CreateRole',
    'CreateServiceLinkedRole',
    'CreateUser',
}


def rule(event):
    # Check if this event is in scope
    if event.get('eventName') not in IAM_ENTITY_CREATION_EVENTS:
        return False

    # All IAM changes MUST go through CloudFormation
    if deep_get(event, 'userIdentity',
                'invokedBy') != 'cloudformation.amazonaws.com':
        return True

    # Only approved IAM Roles can make IAM Changes
    for admin_role_pattern in IAM_ADMIN_ROLE_PATTERNS:
        # Check if the arn matches any role patterns, return False if there is a match
        if (len(
                re.findall(
                    admin_role_pattern,
                    deep_get(event, 'userIdentity', 'sessionContext',
                             'sessionIssuer', 'arn'),
                )) > 0):
            return False

    return (deep_get(event, 'userIdentity', 'sessionContext', 'sessionIssuer',
                     'arn') not in IAM_ADMIN_ROLES)
