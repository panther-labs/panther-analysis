from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    failover_events = ["FailoverDBCluster", "FailoverGlobalCluster"]
    if event.get("eventName") not in failover_events:
        return False
    return event.deep_get("errorCode") is None


def title(event):
    event_name = event.get("eventName", "Unknown")
    cluster_id = event.deep_get("requestParameters", "dBClusterIdentifier") or event.deep_get(
        "requestParameters", "globalClusterIdentifier", default="<UNKNOWN>"
    )
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    cluster_type = "Cluster" if event_name == "FailoverDBCluster" else "Global Cluster"
    return f"RDS {cluster_type} Failover Initiated: [{cluster_id}] by [{user}]"


def alert_context(event):
    context = aws_rds_context(event)
    context["target_identifier"] = event.deep_get(
        "requestParameters", "targetDBInstanceIdentifier"
    ) or event.deep_get("requestParameters", "targetDbClusterIdentifier", default="N/A")
    return context
