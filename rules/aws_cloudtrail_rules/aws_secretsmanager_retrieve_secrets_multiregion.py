from panther_aws_helpers import aws_rule_context


def rule(event):
    return event.get("eventName") == "BatchGetSecretValue"


def unique(event):
    return event.get("awsRegion", "")


def title(event):
    user = event.udm("actor_user")
    return f"[{user}] attempted to retrieve secrets from AWS Secrets Manager in multiple regions"


def alert_context(event):
    return aws_rule_context(event)
