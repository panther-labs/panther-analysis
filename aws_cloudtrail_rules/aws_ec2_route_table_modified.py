from panther import aws_cloudtrail_success

# API calls that are indicative of an EC2 Route Table modification
EC2_RT_MODIFIED_EVENTS = {
    "CreateRoute",
    "CreateRouteTable",
    "ReplaceRoute",
    "ReplaceRouteTableAssociation",
    "DeleteRouteTable",
    "DeleteRoute",
    "DisassociateRouteTable",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in EC2_RT_MODIFIED_EVENTS


def dedup(event):
    return event.get("recipientAccountId")
