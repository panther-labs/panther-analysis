from panther_base_helpers import aws_rule_context

SAML_ACTIONS = ["UpdateSAMLProvider", "CreateSAMLProvider", "DeleteSAMLProvider"]


def rule(event):
    # Allow AWSSSO to manage
    if event.udm("user_arn", default="").endswith(":assumed-role/AWSServiceRoleForSSO/AWS-SSO"):
        return False
    return (
        event.udm("event_source") == "iam.amazonaws.com" and event.udm("event_name") in SAML_ACTIONS
    )


def title(event):
    return (
        f"[{event.udm('user_arn')}] "
        f"performed [{event.udm('event_name')}] "
        f"in account [{event.udm('recipient_account_id')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
