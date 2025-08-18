import json

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_base_helpers import deep_get
from policyuniverse.policy import Policy


# Check if a policy (string or JSON) allows resource accessibility via the Internet
# pylint: disable=too-complex
def policy_is_internet_accessible(policy):
    """
    Check if a policy (string or JSON) allows resource accessibility via the Internet.

    Args:
        policy: A policy object that can be either a string or a JSON object

    Returns:
        bool: True if the policy allows internet access, False otherwise
    """
    # Handle empty policies (None, empty strings, empty dicts, etc.)
    if not policy:
        return False

    # Handle string policies by converting to JSON
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return False

    # Check if the policy has a wildcard principal but also has organization ID restrictions
    # which should not be considered internet accessible
    policy_obj = Policy(policy)

    # If policyuniverse thinks it's not internet accessible, trust that
    if not policy_obj.is_internet_accessible():
        return False

    # For policies with multiple statements, we need to check each statement individually
    # If ANY statement is truly internet accessible, the policy is internet accessible
    has_internet_accessible_statement = False

    for statement in policy_obj.statements:
        if statement.effect != "Allow" or "*" not in statement.principals:
            continue

        # Check if there are organization ID conditions which restrict access
        has_org_condition = False
        for condition in statement.condition_entries:
            if condition.category == "organization":
                has_org_condition = True
                break

        # If this statement has a wildcard principal but no organization ID restrictions,
        # it's truly internet accessible
        if not has_org_condition:
            has_internet_accessible_statement = True
            break

    return has_internet_accessible_statement


def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    parameters = event.get("requestParameters", {})
    # Ignore events that are missing request params
    if not parameters:
        return False

    event_name = event.get("eventName", "")

    # Special case for SNS topic attributes that need additional attribute name check
    if event_name == "SetTopicAttributes" and parameters.get("attributeName", "") == "Policy":
        policy_value = parameters.get("attributeValue", {})
        return policy_is_internet_accessible(policy_value)

    # Map of event names to policy locations in parameters
    policy_location_map = {
        # S3
        "PutBucketPolicy": lambda p: p.get("bucketPolicy", {}),
        # ECR
        "SetRepositoryPolicy": lambda p: p.get("policyText", {}),
        # Elasticsearch
        "CreateElasticsearchDomain": lambda p: p.get("accessPolicies", {}),
        "UpdateElasticsearchDomainConfig": lambda p: p.get("accessPolicies", {}),
        # KMS
        "CreateKey": lambda p: p.get("policy", {}),
        "PutKeyPolicy": lambda p: p.get("policy", {}),
        # S3 Glacier
        "SetVaultAccessPolicy": lambda p: deep_get(p, "policy", "policy", default={}),
        # SNS & SQS
        "SetQueueAttributes": lambda p: deep_get(p, "attributes", "Policy", default={}),
        "CreateTopic": lambda p: deep_get(p, "attributes", "Policy", default={}),
        # SecretsManager
        "PutResourcePolicy": lambda p: p.get("resourcePolicy", {}),
    }

    # Get the policy extraction function for this event name
    policy_extractor = policy_location_map.get(event_name)
    if not policy_extractor:
        return False

    # Extract the policy using the appropriate function
    policy = policy_extractor(parameters)
    return policy_is_internet_accessible(policy)


def title(event):
    # TODO(): Update this rule to use data models
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
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
