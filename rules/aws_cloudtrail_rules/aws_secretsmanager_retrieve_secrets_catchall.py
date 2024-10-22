from panther_aws_helpers import aws_rule_context


def rule(event):
    if event.get("eventName") != "BatchGetSecretValue":
        return False

    filters = event.deep_get("requestParameters", "filters", default=[])
    for filter in filters:
        if filter.get("key") != "tag-key":
            return False
        if any(not value.startswith("!") for value in filter.get("values")):
            return False

    return True


def dedup(event):
    return event.deep_get("userIdentity", "principalId", default="<NO_USER>")


def title(event):
    user = event.deep_get("userIdentity", "principalId", default="<NO_USER>")
    return f"[{user}] attempted to retrieve secrets from AWS Secrets Manager"


def alert_context(event):
    return aws_rule_context(event)
