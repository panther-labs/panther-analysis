from panther_databricks_helpers import DOWNLOAD_ACTIONS, databricks_alert_context


def rule(event):
    action = event.get("actionName")
    if action not in DOWNLOAD_ACTIONS:
        return False

    # Exclude source exports
    if action == "workspaceExport":
        export_format = event.deep_get("requestParams", "workspaceExportFormat")
        if export_format == "SOURCE":
            return False

    # Exclude arrows format
    if action == "downloadQueryResult":
        file_type = event.deep_get("requestParams", "fileType")
        if file_type == "arrows":
            return False

    return True


def dedup(event):
    user = event.deep_get("userIdentity", "email", default="unknown")
    return f"data_download_{user}"


def title(event):
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    action = event.get("actionName", "download")
    return f"High volume data downloads by {user} ({action})"


def alert_context(event):
    return databricks_alert_context(event)
