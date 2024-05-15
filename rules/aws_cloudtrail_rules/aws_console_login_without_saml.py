from panther_base_helpers import aws_rule_context
from panther_default import lookup_aws_account_name


def rule(event):
    return (
        event.udm("event_name") == "ConsoleLogin"
        and event.udm("user_type") != "AssumedRole"
        and not event.udm("saml_provider_arn")
    )


def title(event):
    return (
        f"AWS logins without SAML in account "
        f"[{lookup_aws_account_name(event.udm('recipient_account_id'))}]"
    )


def alert_context(event):
    return aws_rule_context(event)
