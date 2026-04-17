from panther_databricks_helpers import (
    databricks_alert_context,
    extract_group_identifier,
    should_alert_on_group_change,
)


def rule(event):
    return should_alert_on_group_change(event, change_type="delete")


def severity(event):
    status_code = event.deep_get("response", "statusCode")
    return "HIGH" if status_code == 200 else "LOW"


def title(event):
    group_id = extract_group_identifier(event) or "Unknown Group"
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    status_code = event.deep_get("response", "statusCode")
    status = "Success" if status_code == 200 else "Failed"
    return f"Group deletion {status}: {group_id} by {actor}"


def dedup(event):
    group_id = extract_group_identifier(event) or "unknown"
    return f"group_deleted_{group_id}"


def alert_context(event):
    group_id = extract_group_identifier(event)
    return databricks_alert_context(event, additional_fields={"group_id": group_id})
