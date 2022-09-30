from panther_base_helpers import aws_rule_context, deep_get

AWS_USERS_ALLOWED = {
    "DeployRole"
    }

def rule(event):
    if event.get("eventSource") == "ecr.amazonaws.com" and event.get("readOnly") is False:
        aws_username = deep_get(event, "userIdentity", "sessionContext", "sessionIssuer", "userName")
        if aws_username not in AWS_USERS_ALLOWED:
            return True
    return False

def dedup(event):
    return event.get("recipientAccountId")


def alert_context(event):
    return aws_rule_context(event)
