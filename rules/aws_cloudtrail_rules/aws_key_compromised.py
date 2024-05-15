from panther_base_helpers import aws_rule_context

EXPOSED_CRED_POLICY = "AWSExposedCredentialPolicy_DO_NOT_REMOVE"


def rule(event):
    return (
        event.udm("event_name") == "PutUserPolicy"
        and event.udm("policy_name") == EXPOSED_CRED_POLICY
    )


def dedup(event):
    return event.udm("actor_user")


def title(event):
    return (
        f"{dedup(event)}'s access key ID [{event.udm('credential_uid')}]"
        f" was uploaded to a public GitHub repo"
    )


def alert_context(event):
    return aws_rule_context(event)
