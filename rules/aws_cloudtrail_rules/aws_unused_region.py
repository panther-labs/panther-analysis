from panther_base_helpers import aws_rule_context, deep_get

# Define a list of verboten or unused regions
# Could modify to include expected user mappings: { "123456789012": { "us-west-1", "us-east-2" } }
UNUSED_REGIONS = {"ap-east-1", "eu-west-3", "eu-central-1"}


def rule(event):
    if (
        event.get("awsRegion", "<UNKNOWN_AWS_REGION>") in UNUSED_REGIONS
        and event.get("readOnly") is False
    ):
        return True
    return False


def title(event):
    aws_username = deep_get(event, "userIdentity", "sessionContext", "sessionIssuer", "userName")
    return f"Non-read-only API call in unused region {event.get('awsRegion', '<UNKNOWN_AWS_REGION>')} by user {aws_username}"


def alert_context(event):
    return aws_rule_context(event)
