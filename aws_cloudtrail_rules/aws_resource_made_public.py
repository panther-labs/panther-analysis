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
    event_name = event.get('eventName', "")
    policy = ""

    # Handle malformed events
    if not parameters:
        return False
    if event.get('errorCode') == 'AccessDenied' or event_name == "":
        return False
    # S3
    # Don't alert if access is denied
    if event_name == 'PutBucketPolicy':
        return policy_is_not_acceptable(parameters.get('bucketPolicy', None))

    # ECR
    if event_name == 'SetRepositoryPolicy':
        policy = parameters.get('policyText', '{}')

    # Elasticsearch
    if event_name in [
            'CreateElasticsearchDomain', 'UpdateElasticsearchDomainConfig'
    ]:
        policy = parameters.get('accessPolicies', '{}')

    # KMS
    if event_name in ['CreateKey', 'PutKeyPolicy']:
        policy = parameters.get('policy', '{}')

    # S3 Glacier
    if event_name == 'SetVaultAccessPolicy':
        policy = parameters.get('policy', {}).get('policy', '{}')

    # SNS & SQS
    if event_name in ['SetQueueAttributes', 'CreateTopic']:
        policy = parameters.get('attributes', {}).get('Policy', '{}')

    # SNS
    if event_name == 'SetTopicAttributes':
        if parameters.get('attributeName') == 'Policy':
            policy = parameters.get('attributeValue', '{}')
            return policy_is_not_acceptable(json.loads(policy))
        return False

    # SecretsManager
    if event_name == 'PutResourcePolicy':
        policy = parameters.get('resourcePolicy', '{}')

    if policy == "":
        return False

    return False


def title(event):
    # Should use data models for this once that's been rolled out
    user = event['userIdentity'].get('userName') or event['userIdentity'].get(
        'sessionContext').get('sessionIssuer').get('userName')

    if event.get('Resources'):
        return f"AWS Resource {event.get('Resources')[0]['arn']} made public by {user}"

    return f"{event['eventSource']} resource made public by {user}"
