from panther_aws_helpers import aws_rule_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    describe_events = ["DescribeDBSnapshots", "DescribeDBClusterSnapshots"]
    if event.get("eventName") not in describe_events:
        return False
    if event.deep_get("errorCode") is not None:
        return False
    include_public = event.deep_get("requestParameters", "includePublic", default=False)
    include_shared = event.deep_get("requestParameters", "includeShared", default=False)
    if include_public or include_shared:
        return True
    return False


def title(event):
    event_name = event.get("eventName", "Unknown")
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    include_public = event.deep_get("requestParameters", "includePublic", default=False)
    include_shared = event.deep_get("requestParameters", "includeShared", default=False)
    if include_public and include_shared:
        scope = "Public and Shared"
    elif include_public:
        scope = "Public"
    elif include_shared:
        scope = "Shared"
    else:
        scope = "Unknown"
    resource_type = "Snapshots" if event_name == "DescribeDBSnapshots" else "Cluster Snapshots"
    return f"RDS {resource_type} Enumeration: {scope} snapshots queried by [{user}]"


def dedup(event):
    user_arn = event.deep_get("userIdentity", "arn", default="unknown")
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{user_arn}"


def alert_context(event):
    context = aws_rule_context(event)
    context["include_public"] = event.deep_get("requestParameters", "includePublic", default="N/A")
    context["include_shared"] = event.deep_get("requestParameters", "includeShared", default="N/A")
    context["max_records"] = event.deep_get("requestParameters", "maxRecords", default="N/A")
    return context
