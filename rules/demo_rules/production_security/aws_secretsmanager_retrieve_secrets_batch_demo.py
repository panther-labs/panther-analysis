from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    return event.get("eventName") == "BatchGetSecretValue" and aws_cloudtrail_success(event)


def title(event):
    return f"[{event.udm('actor_user')}] attempted to batch retrieve a large number of secrets from AWS Secrets Manager"


def alert_context(event):
    return aws_rule_context(event)
