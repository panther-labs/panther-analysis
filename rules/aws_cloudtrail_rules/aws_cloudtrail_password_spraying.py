from panther_aws_helpers import aws_rule_context
from panther_detection_helpers.caching import increment_counter

MIN_FAILURES = 10
CACHE_TTL = 3600  # matches DedupPeriodMinutes (60 min)


def rule(event):
    if event.get("eventType") != "AwsConsoleSignIn":
        return False
    if event.deep_get("responseElements", "ConsoleLogin", default="") != "Failure":
        return False

    cache_key = (
        f"AWS.CloudTrail.PasswordSpraying:"
        f"{event.get('recipientAccountId', '')}:{event.get('awsRegion', '')}"
    )
    total_failures = increment_counter(cache_key, 1, epoch_seconds=CACHE_TTL)
    return int(total_failures) > MIN_FAILURES


def title(event):
    account = event.get("recipientAccountId", "Unknown Account")
    region = event.get("awsRegion", "Unknown Region")
    return f"Password Spraying Detected in AWS Account [{account}] Region [{region}]"


def dedup(event):
    account = event.get("recipientAccountId", "")
    region = event.get("awsRegion", "")
    return f"{account}:{region}"


def unique(event):
    return event.deep_get("userIdentity", "userName", default="")


def severity(event):
    if event.deep_get("userIdentity", "type", default="") == "Root":
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return aws_rule_context(event)
