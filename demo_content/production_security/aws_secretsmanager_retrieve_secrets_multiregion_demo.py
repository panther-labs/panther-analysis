import json

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "AWS.SecretsManager.RetrieveSecretsMultiRegion"
UNIQUE_REGION_THRESHOLD = 5
WITHIN_TIMEFRAME_MINUTES = 10


def rule(event):
    if event.get("eventName") != "BatchGetSecretValue":
        return False

    if not aws_cloudtrail_success(event):
        return False

    user = event.udm("actor_user")
    key = f"{RULE_ID}-{user}"
    unique_regions = add_to_string_set(key, event.get("awsRegion"), WITHIN_TIMEFRAME_MINUTES * 60)
    if isinstance(unique_regions, str):
        unique_regions = json.loads(unique_regions)
    if len(unique_regions) >= UNIQUE_REGION_THRESHOLD:
        return True
    return False


def title(event):
    user = event.udm("actor_user")
    return f"[{user}] attempted to retrieve secrets from AWS Secrets Manager in multiple regions"


def alert_context(event):
    return aws_rule_context(event)
