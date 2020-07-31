import json
from policyuniverse.policy import Policy

PARAMETER_LOOKUP_MAPPING = {
    'PutBucketPolicy':
        lambda x: x.get('bucketPolicy'),
    'SetVaultAccessPolicy':
        lambda x: json.loads(x.get('policy', {}).get('policy', '{}')),
    'SetQueueAttributes':
        lambda x: json.loads(x.get('attributes', {}).get('Policy', '{}')),
    'CreateTopic':
        lambda x: json.loads(x.get('attributes', {}).get('Policy', '{}')),
    'SetRepositoryPolicy':
        lambda x: json.loads(x.get('policyText', {})),
    'CreateElasticsearchDomain':
        lambda x: json.loads(x.get('accessPolicies', {})),
    'UpdateElasticsearchDomainConfig':
        lambda x: json.loads(x.get('accessPolicies', {})),
    'CreateKey':
        lambda x: json.loads(x.get('policy', {})),
    'PutKeyPolicy':
        lambda x: json.loads(x.get('policy', {})),
    'PutResourcePolicy':
        lambda x: json.loads(x.get('resourcePolicy', {})),
}


# This is a helper function so that the logic determining whether this is an
# acceptable policy can be updated easily.
def policy_is_not_acceptable(json_policy):
    if json_policy is None:
        return False

    return Policy(json_policy).is_internet_accessible()


def rule(event):
    parameters = event.get('requestParameters', {})
    parameter_lookup = PARAMETER_LOOKUP_MAPPING.get(event['eventName'])

    if parameter_lookup:
        policy = parameter_lookup(parameters)
        return policy_is_not_acceptable(policy)

    # SNS special case
    if event['eventName'] == 'SetTopicAttributes':
        if parameters.get('attributeName') == 'Policy':
            policy = parameters.get('attributeValue', '{}')
            return policy_is_not_acceptable(json.loads(policy))
        return False

    return False
