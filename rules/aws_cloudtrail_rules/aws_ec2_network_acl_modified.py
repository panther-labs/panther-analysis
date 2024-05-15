from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# API calls that are indicative of an EC2 Network ACL modification
EC2_NACL_MODIFIED_EVENTS = {
    "CreateNetworkAcl",
    "CreateNetworkAclEntry",
    "DeleteNetworkAcl",
    "DeleteNetworkAclEntry",
    "ReplaceNetworkAclEntry",
    "ReplaceNetworkAclAssociation",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.udm("event_name") in EC2_NACL_MODIFIED_EVENTS


def dedup(event):
    return event.udm("recipient_account_id")


def alert_context(event):
    return aws_rule_context(event)
