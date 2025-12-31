from panther_azureactivity_helpers import azure_resource_logs_success


def rule(event):
    return event.get("operationName", "").upper() == "PUTBLOB" and azure_resource_logs_success(
        event
    )
