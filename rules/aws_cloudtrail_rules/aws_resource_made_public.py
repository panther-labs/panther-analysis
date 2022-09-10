import json

from panther import aws_cloudtrail_success
from panther_base_helpers import aws_rule_context, deep_get
from policyuniverse.policy import Policy


# Check that the IAM policy allows resource accessibility via the Internet
def policy_is_internet_accessible(json_policy):
    if json_policy is None:
        return False
    return Policy(json_policy).is_internet_accessible()


# Normally this check helps avoid overly complex functions that are doing too many things,
# but in this case we explicitly want to handle 10 different cases in 10 different ways.
# Any solution that avoids too many return statements only increases the complexity of this rule.
# pylint: disable=too-many-return-statements, too-complex
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
        return policy_is_internet_accessible(parameters.get("bucketPolicy"))

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
        event,
        "userIdentity",
        "sessionContext",
        "sessionIssuer",
        "userName",
        default="<MISSING_USER>",
    )

    if event.get("Resources"):
        return f"Resource {event.get('Resources')[0].get('arn', 'MISSING')} made public by {user}"

    return f"{event.get('eventSource', 'MISSING SOURCE')} resource made public by {user}"


def alert_context(event):
    return aws_rule_context(event)
