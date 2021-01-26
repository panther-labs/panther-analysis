# API calls that are indicative of an EC2 Network Gateway modification
EC2_GATEWAY_MODIFIED_EVENTS = {
    'CreateCustomerGateway',
    'DeleteCustomerGateway',
    'AttachInternetGateway',
    'CreateInternetGateway',
    'DeleteInternetGateway',
    'DetachInternetGateway',
}


def rule(event):
    return event.get('eventName') in EC2_GATEWAY_MODIFIED_EVENTS


def dedup(event):
    return event.get('recipientAccountId')
