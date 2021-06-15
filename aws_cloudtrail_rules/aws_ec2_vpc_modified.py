from panther import aws_cloudtrail_success

# API calls that are indicative of an EC2 VPC modification
EC2_VPC_MODIFIED_EVENTS = {
    "CreateVpc",
    "DeleteVpc",
    "ModifyVpcAttribute",
    "AcceptVpcPeeringConnection",
    "CreateVpcPeeringConnection",
    "DeleteVpcPeeringConnection",
    "RejectVpcPeeringConnection",
    "AttachClassicLinkVpc",
    "DetachClassicLinkVpc",
    "DisableVpcClassicLink",
    "EnableVpcClassicLink",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in EC2_VPC_MODIFIED_EVENTS


def dedup(event):
    return event.get("recipientAccountId")
