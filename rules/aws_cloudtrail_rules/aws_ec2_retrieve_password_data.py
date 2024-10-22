from panther_aws_helpers import aws_rule_context


def rule(event):
    if event.get("eventName") == "GetPasswordData":
        return True
    return False


def dedup(event):
    return event.deep_get("userIdentity", "principalId", default="<NO_USER>")


def title(event):
    user = event.deep_get("userIdentity", "principalId", default="<NO_USER>")
    return f"[{user}] requested password data for multiple EC2 instances"


def alert_context(event):
    return aws_rule_context(event)
