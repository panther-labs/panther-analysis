# API calls that are indicative of IAM Policy changes
POLICY_CHANGE_EVENTS = {
    'DeleteGroupPolicy',
    'DeleteRolePolicy',
    'DeleteUserPolicy',
    # PutEntityPolicy is for inline policies, these can optionally be split out
    # if inline policies are a greater concern
    ###
    'PutGroupPolicy',
    'PutRolePolicy',
    'PutUserPolicy',
    ###
    'CreatePolicy',
    'DeletePolicy',
    'CreatePolicyVersion',
    'DeletePolicyVersion',
    'AttachRolePolicy',
    'DetachRolePolicy',
    'AttachUserPolicy',
    'DetachUserPolicy',
    'AttachGroupPolicy',
    'DetachGroupPolicy',
}


def rule(event):
    return event['eventName'] in POLICY_CHANGE_EVENTS
