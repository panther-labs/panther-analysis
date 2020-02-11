# API calls that are indicative of an EC2 Network ACL modification
EC2_NACL_MODIFIED_EVENTS = {
    'CreateNetworkAcl',
    'CreateNetworkAclEntry',
    'DeleteNetworkAcl',
    'DeleteNetworkAclEntry',
    'ReplaceNetworkAclEntry',
    'ReplaceNetworkAclAssociation',
}


def rule(event):
    return event['eventName'] in EC2_NACL_MODIFIED_EVENTS
