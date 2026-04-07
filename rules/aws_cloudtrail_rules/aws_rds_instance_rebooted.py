from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    reboot_events = ["RebootDBInstance", "RebootDBCluster", "RebootDBShardGroup"]
    if event.get("eventName") not in reboot_events:
        return False
    return event.deep_get("errorCode") is None


def title(event):
    event_name = event.get("eventName", "Unknown")
    db_identifier = (
        event.deep_get("requestParameters", "dBInstanceIdentifier")
        or event.deep_get("requestParameters", "dBClusterIdentifier")
        or event.deep_get("requestParameters", "dBShardGroupIdentifier", default="<UNKNOWN>")
    )
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    resource_type = (
        "Instance"
        if event_name == "RebootDBInstance"
        else "Cluster" if event_name == "RebootDBCluster" else "Shard Group"
    )
    return f"RDS {resource_type} Rebooted: [{db_identifier}] by [{user}]"


def alert_context(event):
    context = aws_rds_context(event)
    context["force_failover"] = event.deep_get("requestParameters", "forceFailover", default="N/A")
    return context
