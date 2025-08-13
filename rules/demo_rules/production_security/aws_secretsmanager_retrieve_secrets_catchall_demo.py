from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if event.get("eventName") != "BatchGetSecretValue" and not aws_cloudtrail_success(event):
        return False

    filters = event.deep_get("requestParameters", "filters", default=[])
    for filt in filters:
        if filt.get("key") != "tag-key":
            return False
        if any(not value.startswith("!") for value in filt.get("values")):
            return False

    return True


def title(event):
    user = event.udm("actor_user")
    return (
        f"[{user}] attempted to batch retrieve secrets from "
        "AWS Secrets Manager with a catch-all filter"
    )


def alert_context(event):
    return aws_rule_context(event)
