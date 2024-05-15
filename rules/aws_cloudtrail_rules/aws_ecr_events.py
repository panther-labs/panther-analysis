from panther_base_helpers import aws_rule_context

# CONFIGURATION REQUIRED: Update with your expected AWS Accounts/Regions
AWS_ACCOUNTS_AND_REGIONS = {
    "123456789012": {"us-west-1", "us-west-2"},
    "103456789012": {"us-east-1", "us-east-2"},
}


def rule(event):
    if event.udm("event_source") == "ecr.amazonaws.com":
        aws_account_id = event.udm("user_account_id")
        if aws_account_id in AWS_ACCOUNTS_AND_REGIONS:
            if event.udm("cloud_region") not in AWS_ACCOUNTS_AND_REGIONS[aws_account_id]:
                return True
        else:
            return True
    return False


def dedup(event):
    return event.udm("recipient_account_id")


def alert_context(event):
    return aws_rule_context(event)
