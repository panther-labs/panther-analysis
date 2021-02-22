from panther_base_helpers import deep_get


def rule(event):
    # Only check actions creating a new Network ACL entry
    if event.get("eventName") != "CreateNetworkAclEntry":
        return False

    # Check if this new NACL entry is allowing traffic from anywhere
    return (
        deep_get(event, "requestParameters", "cidrBlock") == "0.0.0.0/0"
        and deep_get(event, "requestParameters", "ruleAction") == "allow"
        and deep_get(event, "requestParameters", "egress") is False
    )
