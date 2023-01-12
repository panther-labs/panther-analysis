from panther_base_helpers import aws_rule_context, deep_get

DISCOVERY_EVENTS = [
    "DescribeAutoScalingGroups",
    "DescribeCloudFormationStacks",
    "DescribeDBInstances",
    "DescribeImages",
    "DescribeInstances",
    "DescribeInternetGateways",
    "DescribeKeyPairs",
    "DescribeLambdaFunctions",
    "DescribeLaunchConfigurations",
    "DescribeNetworkInterfaces",
    "DescribeRouteTables",
    "DescribeS3Buckets",
    "DescribeSecurityGroups",
    "DescribeSnapshots",
    "DescribeSubnets",
    "DescribeTables",
    "DescribeVolumes",
    "DescribeVpcs",
    "ListAutoScalingGroups",
    "ListCloudFormationStacks" "ListDBInstances",
    "ListImages",
    "ListInstances",
    "ListInternetGateways",
    "ListKeyPairs",
    "ListLambdaFunctions",
    "ListLaunchConfigurations",
    "ListNetworkInterfaces",
    "ListRouteTables",
    "ListS3Buckets",
    "ListSecurityGroups",
    "ListSnapshots",
    "ListSubnets",
    "ListTables",
    "ListVolumes",
    "ListVpcs",
]


def rule(event):
    return event.get("eventName") in DISCOVERY_EVENTS


def title(event):
    user_arn = deep_get(event, "useridentity", "arn", default="<MISSING_ARN>")
    return (
        f"Cloud Infrastructure Discovery detected in AWS CloudTrail from [{user_arn}]"
    )


def alert_context(event):
    return aws_rule_context(event)
