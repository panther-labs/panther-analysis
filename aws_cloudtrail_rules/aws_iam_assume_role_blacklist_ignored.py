from panther_base_helpers import deep_get

# This is a list of role ARNs that should not be assumed by users in normal operations
ASSUME_ROLE_BLACKLIST = [
    'arn:aws:iam::123456789012:role/FullAdminRole',
]


def rule(event):
    # Only considering the AssumeRole action
    if event['eventName'] != 'AssumeRole':
        return False

    # Only considering user actions
    if deep_get(event, 'userIdentity',
                'type') not in ['IAMUser', 'FederatedUser']:
        return False

    return deep_get(event, 'requestParameters',
                    'roleArn') in ASSUME_ROLE_BLACKLIST
