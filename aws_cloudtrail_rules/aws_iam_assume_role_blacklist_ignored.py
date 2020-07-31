# This is a list of role ARNs that should not be assumed by users in normal operations
ASSUME_ROLE_BLACKLIST = [
    'arn:aws:iam::123456789012:role/FullAdminRole',
]


def rule(event):
    # Only considering the AssumeRole action
    if event['eventName'] != 'AssumeRole':
        return False

    # Only considering user actions
    if event['userIdentity']['type'] not in ['IAMUser', 'FederatedUser']:
        return False

    return event['requestParameters']['roleArn'] in ASSUME_ROLE_BLACKLIST
