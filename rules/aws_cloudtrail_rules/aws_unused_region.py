from panther_base_helpers import aws_rule_context

# Define a list of verboten or unused regions
# Could modify to include expected user mappings: { "123456789012": { "us-west-1", "us-east-2" } }
UNUSED_REGIONS = {"ap-east-1", "eu-west-3", "eu-central-1"}


def rule(event):
    if (
        event.udm("cloud_region", default="<UNKNOWN_AWS_REGION>") in UNUSED_REGIONS
        and event.udm("read_only") is False
    ):
        return True
    return False


def title(event):
    aws_user_arn = event.udm("session_issuer_arn", default="<USER_NOT_FOUND>")
    return (
        "Non-read-only API call in unused region"
        f" {event.udm('cloud_region', default='<UNKNOWN_AWS_REGION>')} by user {aws_user_arn}"
    )


def alert_context(event):
    return aws_rule_context(event)
