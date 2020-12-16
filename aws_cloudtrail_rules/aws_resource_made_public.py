import json
from policyuniverse.policy import Policy


# This is a helper function so that the logic determining whether this is an
# acceptable policy can be updated easily.
def policy_is_not_acceptable(json_policy):
    if json_policy is None:
        return False

    return Policy(json_policy).is_internet_accessible()


# Normally this check helps avoid overly complex functions that are doing too many things,
# but in this case we explicitly want to handle 10 different cases in 10 different ways. Any
# solution that avoids too many return statements only increases the complexity of this rule.
# pylint: disable=too-many-return-statements
def rule(event):
    parameters = event.get('requestParameters', {})

    if not parameters:
        return False
    if event.get('errorCode') == 'AccessDenied':
        return False
    # S3
    if event['eventName'] == 'PutBucketPolicy':
        # Don't alert if access is denied
        return policy_is_not_acceptable(parameters.get('bucketPolicy', None))

    # ECR
    if event['eventName'] == 'SetRepositoryPolicy':
        policy = parameters.get('policyText', '{}')

    # Elasticsearch
    if event['eventName'] in [
            'CreateElasticsearchDomain', 'UpdateElasticsearchDomainConfig'
    ]:
        policy = parameters.get('accessPolicies', '{}')

    # KMS
    if event['eventName'] in ['CreateKey', 'PutKeyPolicy']:
        policy = parameters.get('policy', '{}')

    # S3 Glacier
    if event['eventName'] == 'SetVaultAccessPolicy':
        policy = parameters.get('policy', {}).get('policy', '{}')

    # SNS & SQS
    if event['eventName'] in ['SetQueueAttributes', 'CreateTopic']:
        policy = parameters.get('attributes', {}).get('Policy', '{}')

    # SNS
    if event['eventName'] == 'SetTopicAttributes':
        if parameters.get('attributeName') == 'Policy':
            policy = parameters.get('attributeValue', '{}')
            return policy_is_not_acceptable(json.loads(policy))
        return False

    # SecretsManager
    if event['eventName'] == 'PutResourcePolicy':
        policy = parameters.get('resourcePolicy', '{}')

    if len(policy) == 0:
        return False

    return policy_is_not_acceptable(json.loads(policy))
