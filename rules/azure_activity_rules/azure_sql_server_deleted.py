from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

SQL_SERVER_DELETE = "MICROSOFT.SQL/SERVERS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == SQL_SERVER_DELETE and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "")
    sql_server = extract_resource_name_from_id(
        resource_id, "servers", default="<UNKNOWN_SQL_SERVER>"
    )

    return f"Azure SQL Server deleted [{sql_server}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
