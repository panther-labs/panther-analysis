from panther_base_helpers import aws_rule_context

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
    return event.udm("event_name") in DISCOVERY_EVENTS


def title(event):
    return (
        f"User [{event.udm('user_principal_id')}] "
        f"performed a [{event.udm('event_name')}] "
        f"action in AWS account [{event.udm('recipient_account_id')}]."
    )


def dedup(event):
    return event.udm("user_principal_id")


def alert_context(event):
    return aws_rule_context(event)
