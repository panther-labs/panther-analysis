from panther_aws_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success


def rule(event):
    # Only check successful actions creating a new Network ACL entry
    if not aws_cloudtrail_success(event) or event.get("eventName") != "CreateNetworkAclEntry":
        return False

    # Check if this new NACL entry is allowing traffic from anywhere
    return (
        event.deep_get("requestParameters", "cidrBlock") == "0.0.0.0/0"
        and event.deep_get("requestParameters", "ruleAction") == "allow"
        and event.deep_get("requestParameters", "egress") is False
    )


def alert_context(event):
    return aws_rule_context(event)
