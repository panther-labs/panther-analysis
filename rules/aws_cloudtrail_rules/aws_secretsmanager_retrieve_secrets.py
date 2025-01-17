from panther_aws_helpers import aws_rule_context


def rule(event):
    if event.get("eventName") == "GetSecretValue":
        return True
    return False


def title(event):
    user = event.udm("actor_user")
    return f"[{user}] attempted to retrieve a large number of secrets from AWS Secrets Manager"


def alert_context(event):
    return aws_rule_context(event)
