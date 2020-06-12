# API calls that are indicative of an EC2 Route Table modification
EC2_RT_MODIFIED_EVENTS = {
    'CreateRoute',
    'CreateRouteTable',
    'ReplaceRoute',
    'ReplaceRouteTableAssociation',
    'DeleteRouteTable',
    'DeleteRoute',
    'DisassociateRouteTable',
}


def rule(event):
    return event['eventName'] in EC2_RT_MODIFIED_EVENTS


def dedup(event):
    return event.get('recipientAccountId')
