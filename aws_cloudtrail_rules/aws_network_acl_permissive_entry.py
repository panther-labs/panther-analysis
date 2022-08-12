from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get, aws_rule_context


def rule(event):
    # Only check successful actions creating a new Network ACL entry
    if not aws_cloudtrail_success(event) or event.get("eventName") != "CreateNetworkAclEntry":
        return False

    # Check if this new NACL entry is allowing traffic from anywhere
    return (
        deep_get(event, "requestParameters", "cidrBlock") == "0.0.0.0/0"
        and deep_get(event, "requestParameters", "ruleAction") == "allow"
        and deep_get(event, "requestParameters", "egress") is False
    )


def alert_context(event):
    return aws_rule_context(event)
