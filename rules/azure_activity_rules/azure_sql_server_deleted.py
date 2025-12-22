from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

SQL_SERVER_DELETE = "MICROSOFT.SQL/SERVERS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == SQL_SERVER_DELETE and azure_activity_success(
        event
    )


def title(event):
    sql_server = event.deep_get("resourceId", default="<UNKNOWN_SQL_SERVER>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")

    return f"Azure SQL Server deleted [{sql_server}] from [{caller}]"


def alert_context(event):
    return azure_activity_alert_context(event)
