# The role dedicated for IAM administration
IAM_ADMIN_ROLES = {
    'arn:aws:iam::123456789012:role/IdentityCFNServiceRole',
}

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
    if event['eventName'] not in IAM_ENTITY_CREATION_EVENTS:
        return False

    # All IAM changes MUST go through CloudFormation
    if event['userIdentity'].get('invokedBy') != 'cloudformation.amazonaws.com':
        return True

    # Only approved IAM Roles can make IAM Changes
    return event['userIdentity']['sessionContext']['sessionIssuer'][
        'arn'] not in IAM_ADMIN_ROLES
