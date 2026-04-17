from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

PUBLIC_IP_READ = "MICROSOFT.NETWORK/PUBLICIPADDRESSES/READ"
VM_READ = "MICROSOFT.COMPUTE/VIRTUALMACHINES/READ"


def rule(event):
    operation = event.get("operationName", "").upper()
    return all(
        [
            operation in [PUBLIC_IP_READ, VM_READ],
            azure_activity_success(event),
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    operation = event.get("operationName", "").upper()

    if operation == PUBLIC_IP_READ:
        resource_type = "Public IP Address"
    elif operation == VM_READ:
        resource_type = "Virtual Machine"
    else:
        resource_type = "Resource"

    return f"Azure Excessive {resource_type} Read on [{resource_id}]"


def alert_context(event):
    return azure_activity_alert_context(event)
