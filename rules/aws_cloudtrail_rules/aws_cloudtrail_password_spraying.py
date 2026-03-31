from panther_aws_helpers import aws_rule_context


def rule(event):
    if event.get("eventType") != "AwsConsoleSignIn":
        return False
    return event.deep_get("responseElements", "ConsoleLogin", default="") == "Failure"


def title(event):
    account = event.get("recipientAccountId", "Unknown Account")
    region = event.get("awsRegion", "Unknown Region")
    return f"Password Spraying Detected in AWS Account [{account}] Region [{region}]"


def dedup(event):
    account = event.get("recipientAccountId", "")
    region = event.get("awsRegion", "")
    return f"{account}:{region}"


def unique(event):
    return event.deep_get("userIdentity", "userName") or None


def severity(event):
    if event.deep_get("userIdentity", "type", default="") == "Root":
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return aws_rule_context(event)
