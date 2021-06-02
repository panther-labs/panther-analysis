from panther import aws_cloudtrail_success

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
    return aws_cloudtrail_success(event) and event.get("eventName") in EC2_NACL_MODIFIED_EVENTS


def dedup(event):
    return event.get("recipientAccountId")
