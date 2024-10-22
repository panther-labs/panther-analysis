from panther_aws_helpers import aws_rule_context
from panther_detection_helpers import add_to_string_set

RULE_ID = "AWS.SecretsManager.RetrieveSecretsMultiRegion"
UNIQUE_REGION_THRESHOLD = 5
WITHIN_TIMEFRAME_MINUTES = 10


def rule(event):
    if event.get("eventName") != "GetSecretValueBatch":
        return False
    user = event.deep_get("userIdentity", "principalId", default="<NO_USER>")
    key = f"{RULE_ID}-{user}"
    unique_regions = add_to_string_set(key, event.get("awsRegion"), WITHIN_TIMEFRAME_MINUTES * 60)
    if len(unique_regions) >= UNIQUE_REGION_THRESHOLD:
        return True
    return False


def dedup(event):
    return event.deep_get("userIdentity", "principalId", default="<NO_USER>")


def title(event):
    user = event.deep_get("userIdentity", "principalId", default="<NO_USER>")
    return f"[{user}] attempted to retrieve secrets from AWS Secrets Manager"


def alert_context(event):
    return aws_rule_context(event)
