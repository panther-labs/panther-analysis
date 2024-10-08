from panther_aws_helpers import aws_rule_context

DISCOVERY_EVENTS = [
    "ListDocuments",
    "ListMembers",
    "DescribeProducts",
    "DescribeStandards",
    "DescribeStandardsControls",
    "DescribeInstanceInformation",
    "DescribeSecurityGroups",
    "DescribeSecurityGroupRules",
    "DescribeSecurityGroupReferences",
    "DescribeSubnets",
    "DescribeHub",
    "ListFirewalls",
    "ListRuleGroups",
    "ListFirewallPolicies",
    "DescribeFirewall",
    "DescribeFirewallPolicy",
    "DescribeLoggingConfiguration",
    "DescribeResourcePolicy",
    "DescribeRuleGroup",
]


def rule(event):
    return event.get("eventName") in DISCOVERY_EVENTS


def title(event):
    return (
        f"User [{event.deep_get('userIdentity', 'principalId')}] "
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )


def dedup(event):
    return event.deep_get("userIdentity", "principalId", default="NO_PRINCIPAL_ID_FOUND")


def alert_context(event):
    return aws_rule_context(event)
