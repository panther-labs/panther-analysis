import re

from panther_aws_helpers import aws_rule_context
from panther_detection_helpers import add_to_string_set

RULE_ID = "AWS.EC2.DiscoveryCommands"
UNIQUE_COMMAND_THRESHOLD = 3
WITHIN_TIMEFRAME_MINUTES = 10
DISCOVERY_COMMANDS = {
    "GetCallerIdentity",
    "ListBuckets",
    "GetAccountSummary",
    "ListRoles",
    "ListUsers",
    "GetAccountAuthorizationDetails",
    "DescribeSnapshots",
    "DescribeTrails",
    "ListDetectors",
}


def rule(event):
    command = event.get("eventName")
    if command not in DISCOVERY_COMMANDS:
        return False
    arn = event.deep_get("userIdentity", "arn", default="<NO_ARN>")
    instance_id = re.search(r"i-[a-f0-9]+$", arn)
    if not instance_id:
        return False
    key = f"{RULE_ID}-{instance_id.group()}"
    unique_commands = add_to_string_set(key, command, WITHIN_TIMEFRAME_MINUTES * 60)
    if len(unique_commands) >= UNIQUE_COMMAND_THRESHOLD:
        return True
    return False


def dedup(event):
    return event.deep_get("userIdentity", "arn", default="<NO_USER>")


def title(event):
    user = event.deep_get("userIdentity", "arn", default="<NO_USER>")
    return f"[{user}] attempted to retrieve secrets from AWS Secrets Manager"


def alert_context(event):
    return aws_rule_context(event)
