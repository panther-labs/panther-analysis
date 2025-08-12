from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "DeleteFlowLogs"


def title(event):
    account = event.deep_get("userIdentity", "accountId", default="<UNKNOWN ACCOUNT>")
    region = event.get("awsRegion", "<UNKNOWN REGION>")
    return f"VPC Flow logs have been deleted in {account} in {region}"


def alert_context(event):
    return aws_rule_context(event)
