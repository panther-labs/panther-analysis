import json
from policyuniverse.policy import Policy

API_TO_PARAMETER_MAPPING = {
    'SetRepositoryPolicy': 'policyText',
    'CreateElasticsearchDomain': 'accessPolicies',
    'UpdateElasticsearchDomainConfig': 'accessPolicies',
    'CreateKey': 'policy',
    'PutKeyPolicy': 'policy',
    'PutResourcePolicy': 'resourcePolicy',
}


# This is a helper function so that the logic determining whether this is an
# acceptable policy can be updated easily.
def policy_is_not_acceptable(json_policy):
    if json_policy is None:
        return False

    return Policy(json_policy).is_internet_accessible()


def rule(event):
    parameters = event.get('requestParameters', {})

    parameter_name = API_TO_PARAMETER_MAPPING.get(event['eventName'], '{}')
    if parameter_name:
        policy = parameters.get(parameter_name, '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # S3
    if event['eventName'] == 'PutBucketPolicy':
        return policy_is_not_acceptable(parameters.get('bucketPolicy', None))

    # S3 Glacier
    if event['eventName'] == 'SetVaultAccessPolicy':
        policy = parameters.get('policy', {}).get('policy', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # SQS
    if event['eventName'] in ['SetQueueAttributes', 'CreateTopic']:
        policy = parameters.get('attributes', {}).get('Policy', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # SNS
    if event['eventName'] == 'SetTopicAttributes':
        if parameters.get('attributeName') == 'Policy':
            policy = parameters.get('attributeValue', '{}')
            return policy_is_not_acceptable(json.loads(policy))
        return False

    return False
