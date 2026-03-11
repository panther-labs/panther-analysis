def rule(event):
    # Alert on Salesforce Bulk API Result Events
    # These events are generated when bulk API jobs complete
    # and can indicate large-scale data exfiltration attempts
    return event.get("EVENT_TYPE") == "BulkApiResultEventStore"


def title(event):
    # Create descriptive title with operation and volume details
    user = event.get("USER_NAME", event.get("USER_ID", "<UNKNOWN_USER>"))
    operation = event.get("OPERATION_TYPE", "<UNKNOWN_OPERATION>")
    records = event.get("RECORDS_PROCESSED", 0)
    entity = event.get("ENTITY_NAME", "<UNKNOWN_ENTITY>")

    return f"Salesforce Bulk API: {operation} on {entity} ({records:,} records) - User: {user}"


def severity(event):
    # Map based on operation type and volume
    operation = event.get("OPERATION_TYPE", "")
    records = event.get("RECORDS_PROCESSED", 0)
    # Ensure records is numeric
    records = records if isinstance(records, (int, float)) else 0

    # Query operations are most concerning for data exfiltration
    if operation in ["query", "queryAll"]:
        if records >= 100000:
            severity_level = "CRITICAL"
        elif records >= 50000:
            severity_level = "HIGH"
        elif records >= 10000:
            severity_level = "MEDIUM"
        else:
            severity_level = "DEFAULT"
    # Other operations (insert, update, delete) are also notable
    elif operation in ["delete", "hardDelete"]:
        if records >= 10000:
            severity_level = "HIGH"
        elif records >= 1000:
            severity_level = "MEDIUM"
        else:
            severity_level = "DEFAULT"
    # Default for other operations
    else:
        if records >= 50000:
            severity_level = "HIGH"
        elif records >= 10000:
            severity_level = "MEDIUM"
        else:
            severity_level = "DEFAULT"

    return severity_level


def dedup(event):
    # Deduplicate by job ID to avoid duplicate alerts for the same job
    job_id = event.get("JOB_ID", "unknown")
    return f"SF_BULK_API_{job_id}"


def alert_context(event):
    # Provide comprehensive context for investigation
    return {
        "Job ID": event.get("JOB_ID"),
        "User ID": event.get("USER_ID"),
        "Username": event.get("USER_NAME"),
        "Operation Type": event.get("OPERATION_TYPE"),
        "Entity Name": event.get("ENTITY_NAME"),
        "Records Processed": event.get("RECORDS_PROCESSED"),
        "Number of Batches": event.get("NUMBER_OF_BATCHES"),
        "API Version": event.get("API_VERSION"),
        "Source IP": event.get("SOURCE_IP"),
        "Request ID": event.get("REQUEST_ID"),
        "Organization ID": event.get("ORGANIZATION_ID"),
        "Job Type": event.get("JOB_TYPE"),
    }
