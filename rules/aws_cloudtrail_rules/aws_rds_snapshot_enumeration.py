from panther_aws_helpers import aws_rule_context
from panther_base_helpers import deep_get


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    describe_events = ["DescribeDBSnapshots", "DescribeDBClusterSnapshots"]
    if event.get("eventName") not in describe_events:
        return False
    if deep_get(event, "errorCode"):
        return False
    include_public = deep_get(event, "requestParameters", "includePublic", default=False)
    include_shared = deep_get(event, "requestParameters", "includeShared", default=False)
    if include_public or include_shared:
        return True
    return False


def title(event):
    event_name = event.get("eventName", "Unknown")
    user = deep_get(event, "userIdentity", "userName") or deep_get(
        event, "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    include_public = deep_get(event, "requestParameters", "includePublic", default=False)
    include_shared = deep_get(event, "requestParameters", "includeShared", default=False)
    scope = "Public" if include_public else "Shared" if include_shared else "Unknown"
    resource_type = "Snapshots" if event_name == "DescribeDBSnapshots" else "Cluster Snapshots"
    return f"RDS {resource_type} Enumeration: {scope} snapshots queried by [{user}]"


def dedup(event):
    user_arn = deep_get(event, "userIdentity", "arn", default="unknown")
    account_id = deep_get(event, "recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{user_arn}"


def alert_context(event):
    context = aws_rule_context(event)
    context["include_public"] = deep_get(event, "requestParameters", "includePublic", default="N/A")
    context["include_shared"] = deep_get(event, "requestParameters", "includeShared", default="N/A")
    context["max_records"] = deep_get(event, "requestParameters", "maxRecords", default="N/A")
    return context
