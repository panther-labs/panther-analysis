from panther_base_helpers import aws_rule_context

SAML_ACTIONS = ["UpdateSAMLProvider", "CreateSAMLProvider", "DeleteSAMLProvider"]


def rule(event):
    # Allow AWSSSO to manage
    if event.deep_get("userIdentity", "arn", default="").endswith(
        ":assumed-role/AWSServiceRoleForSSO/AWS-SSO"
    ):
        return False
    # Don't alert on errors such as EntityAlreadyExistsException and NoSuchEntity
    if event.get("errorCode"):
        return False
    return (
        event.get("eventSource") == "iam.amazonaws.com" and event.get("eventName") in SAML_ACTIONS
    )


def title(event):
    return (
        f"[{event.deep_get('userIdentity','arn')}] "
        f"performed [{event.get('eventName')}] "
        f"in account [{event.get('recipientAccountId')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
