def rule(event):
    # Only check actions creating a new Network ACL entry
    if event['eventName'] != 'CreateNetworkAclEntry':
        return False

    # Check if this new NACL entry is allowing traffic from anywhere
    return (event['requestParameters']['cidrBlock'] == '0.0.0.0/0' and
            event['requestParameters']['ruleAction'] == 'allow' and
            event['requestParameters']['egress'] is False)
