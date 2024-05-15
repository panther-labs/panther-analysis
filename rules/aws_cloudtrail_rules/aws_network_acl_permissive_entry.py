from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success


def rule(event):
    # Only check successful actions creating a new Network ACL entry
    if not aws_cloudtrail_success(event) or event.udm("event_name") != "CreateNetworkAclEntry":
        return False

    # Check if this new NACL entry is allowing traffic from anywhere
    return (
        event.udm("cidr_block") == "0.0.0.0/0"
        and event.udm("rule_action") == "allow"
        and event.udm("egress") is False
    )


def alert_context(event):
    return aws_rule_context(event)
