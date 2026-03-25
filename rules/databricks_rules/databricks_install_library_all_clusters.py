from panther_databricks_helpers import databricks_alert_context


def rule(event):
    return event.get("actionName") == "installLibraryOnAllClusters"


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    workspace = event.get("workspaceId", "Unknown Workspace")
    return f"Library installed on all clusters in workspace {workspace} by {actor}"


def alert_context(event):
    return databricks_alert_context(
        event, additional_fields={"library_config": event.get("requestParams")}
    )
