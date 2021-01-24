from panther_base_helpers import deep_get, pattern_match_list

PROD_ACCOUNT_IDS = {'11111111111111', '112233445566'}
SG_CHANGE_EVENTS = {
    'CreateSecurityGroup': {
        'fields': ['groupName', 'vpcId'],
        'title': 'New security group [{groupName}] created by {actor}',
    },
    'AuthorizeSecurityGroupIngress': {
        'fields': ['groupId'],
        'title': 'User {actor} has updated security group [{groupId}]',
    },
    'AuthorizeSecurityGroupEgress': {
        'fields': ['groupId'],
        'title': 'User {actor} has updated security group [{groupId}]',
    },
}

ALLOWED_USER_AGENTS = {
    '* HashiCorp/?.0 Terraform/*',
    # 'console.ec2.amazonaws.com',
    # 'cloudformation.amazonaws.com',
}


def rule(event):
    return (event.get('eventName') in SG_CHANGE_EVENTS.keys() and
            event.get('recipientAccountId') in PROD_ACCOUNT_IDS and
            not pattern_match_list(event.get('userAgent'), ALLOWED_USER_AGENTS))


def dedup(event):
    return ':'.join(
        deep_get(event, 'requestParameters', name)
        for name in SG_CHANGE_EVENTS[event.get('eventName')]['fields'])


def title(event):
    title_fields = {
        name: deep_get(event, 'requestParameters', name)
        for name in SG_CHANGE_EVENTS[event.get('eventName')]['fields']
    }
    user = deep_get(event, 'userIdentity', 'arn', default='UNKNOWN').split('/')[-1]
    title_template = SG_CHANGE_EVENTS[event.get('eventName')]['title']
    title_fields['actor'] = user
    return title_template.format(**title_fields)
