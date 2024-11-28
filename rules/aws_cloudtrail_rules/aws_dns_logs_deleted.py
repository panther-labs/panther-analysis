from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


def rule(event):
    return (
        aws_cloudtrail_success(event) and event.get("eventName") == "DeleteResolverQueryLogConfig"
    )


def title(event):
    account = event.deep_get("userIdentity", "accountId", default="<UNKNOWN ACCOUNT>")
    region = event.get("awsRegion", "<UNKNOWN REGION>")
    return f"DNS logs have been deleted in {lookup_aws_account_name(account)} in {region}"


def alert_context(event):
    log_id = event.deep_get("requestParameters", "resolverQueryLogConfigId", "<UNKNOWN LOG ID>")
    return aws_rule_context(event) | {"logId": log_id}
