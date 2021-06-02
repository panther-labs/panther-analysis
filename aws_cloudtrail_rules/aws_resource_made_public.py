import json

from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get
from policyuniverse.policy import Policy

try:
    # This is a temporary workaround so that the rule doesn't break in Panther 1.15.x.
    # It can be removed either by using the deep-copy methods
    # defined in https://github.com/panther-labs/panther/pull/2630
    # or by upgrading to a new policyuniverse release.
    # For details see: https://github.com/panther-labs/panther/issues/2550
    from src.enriched_event import PantherEvent

    PANTHER_JSON_ENCODER = PantherEvent.json_encoder
except ImportError:
    PANTHER_JSON_ENCODER = None


# Check that the IAM policy allows resource accessibility via the Internet
def policy_is_internet_accessible(json_policy):
    if json_policy is None:
        return False
    return Policy(json_policy).is_internet_accessible()


# Normally this check helps avoid overly complex functions that are doing too many things,
# but in this case we explicitly want to handle 10 different cases in 10 different ways.
# Any solution that avoids too many return statements only increases the complexity of this rule.
# pylint: disable=too-many-return-statements
def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    parameters = event.get("requestParameters", {})
    # Ignore events that are missing request params
    if not parameters:
        return False

    policy = ""

    # S3
    if event["eventName"] == "PutBucketPolicy":
        return policy_is_internet_accessible(
            json.loads(json.dumps(parameters.get("bucketPolicy"), default=PANTHER_JSON_ENCODER))
        )

    # ECR
    if event["eventName"] == "SetRepositoryPolicy":
        policy = parameters.get("policyText", {})

    # Elasticsearch
    if event["eventName"] in ["CreateElasticsearchDomain", "UpdateElasticsearchDomainConfig"]:
        policy = parameters.get("accessPolicies", {})

    # KMS
    if event["eventName"] in ["CreateKey", "PutKeyPolicy"]:
        policy = parameters.get("policy", {})

    # S3 Glacier
    if event["eventName"] == "SetVaultAccessPolicy":
        policy = deep_get(parameters, "policy", "policy", default={})

    # SNS & SQS
    if event["eventName"] in ["SetQueueAttributes", "CreateTopic"]:
        policy = deep_get(parameters, "attributes", "Policy", default={})

    # SNS
    if (
        event["eventName"] == "SetTopicAttributes"
        and parameters.get("attributeName", "") == "Policy"
    ):
        policy = parameters.get("attributeValue", {})

    # SecretsManager
    if event["eventName"] == "PutResourcePolicy":
        policy = parameters.get("resourcePolicy", {})

    if not policy:
        return False

    return policy_is_internet_accessible(json.loads(policy))


def title(event):
    # TODO(): Update this rule to use data models
    user = deep_get(event, "userIdentity", "userName") or deep_get(
        event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
    )

    if event.get("Resources"):
        return f"Resource {event.get('Resources')[0].get('arn', 'MISSING')} made public by {user}"

    return f"{event.get('eventSource', 'MISSING SOURCE')} resource made public by {user}"
