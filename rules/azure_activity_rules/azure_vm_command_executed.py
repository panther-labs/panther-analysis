from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

VM_RUN_COMMAND = "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"


def rule(event):
    return event.get("operationName", "").upper() == VM_RUN_COMMAND and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    vm_name = "<UNKNOWN_VM>"
    if resource_id:
        parts = resource_id.split("/")
        if "virtualMachines" in parts:
            try:
                vm_name = parts[parts.index("virtualMachines") + 1]
            except (IndexError, ValueError):
                pass

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    return f"Command Executed on Azure VM [{vm_name}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "virtualMachines" in parts:
            try:
                context["vm_name"] = parts[parts.index("virtualMachines") + 1]
            except (IndexError, ValueError):
                pass

    return context
