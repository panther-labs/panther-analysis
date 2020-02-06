# API calls that are indicative of an EC2 VPC modification
EC2_VPC_MODIFIED_EVENTS = {
    'CreateVpc',
    'DeleteVpc',
    'ModifyVpcAttribute',
    'AcceptVpcPeeringConnection',
    'CreateVpcPeeringConnection',
    'DeleteVpcPeeringConnection',
    'RejectVpcPeeringConnection',
    'AttachClassicLinkVpc',
    'DetachClassicLinkVpc',
    'DisableVpcClassicLink',
    'EnableVpcClassicLink',
}


def rule(event):
    return event['eventName'] in EC2_VPC_MODIFIED_EVENTS
