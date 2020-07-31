import json
from policyuniverse.policy import Policy


# This is a helper function so that the logic determining whether this is an
# acceptable policy can be updated easily.
def policy_is_not_acceptable(json_policy):
    if json_policy is None:
        return False

    return Policy(json_policy).is_internet_accessible()


def rule(event):
    parameters = event.get('requestParameters', {})

    # S3
    if event['eventName'] == 'PutBucketPolicy':
        return policy_is_not_acceptable(parameters.get('bucketPolicy', None))

    # ECR
    if event['eventName'] == 'SetRepositoryPolicy':
        policy = parameters.get('policyText', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # Elasticsearch
    if event['eventName'] in [
            'CreateElasticsearchDomain', 'UpdateElasticsearchDomainConfig'
    ]:
        policy = parameters.get('accessPolicies', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # KMS
    if event['eventName'] in ['CreateKey', 'PutKeyPolicy']:
        policy = parameters.get('policy', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # S3 Glacier
    if event['eventName'] == 'SetVaultAccessPolicy':
        policy = parameters.get('policy', {}).get('policy', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # SNS & SQS
    if event['eventName'] in ['SetQueueAttributes', 'CreateTopic']:
        policy = parameters.get('attributes', {}).get('Policy', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    # SNS
    if event['eventName'] == 'SetTopicAttributes':
        if parameters.get('attributeName') == 'Policy':
            policy = parameters.get('attributeValue', '{}')
            return policy_is_not_acceptable(json.loads(policy))
        return False

    # SecretsManager
    if event['eventName'] == 'PutResourcePolicy':
        policy = parameters.get('resourcePolicy', '{}')
        return policy_is_not_acceptable(json.loads(policy))

    return False
