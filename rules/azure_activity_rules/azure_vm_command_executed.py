from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

# AZT301.1 - RunCommand
VM_RUN_COMMAND = "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"

# AZT301.2 & AZT301.3 - CustomScriptExtension and DSC
VM_EXTENSIONS_WRITE = "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE"

# AZT301.4 - Compute Gallery Application
GALLERY_APP_WRITE = "MICROSOFT.COMPUTE/GALLERIES/APPLICATIONS/VERSIONS/WRITE"

# AZT301.5 - AKS Command Invoke
AKS_RUN_COMMAND = "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/RUNCOMMAND/ACTION"

# AZT301.6 - VMSS Run Command
VMSS_RUN_COMMAND = "MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/VIRTUALMACHINES/RUNCOMMAND/ACTION"

# AZT301.7 - Serial Console
SERIAL_CONSOLE_CONNECT = "MICROSOFT.SERIALCONSOLE/SERIALPORTS/CONNECT/ACTION"

AZT301_OPERATIONS = [
    VM_RUN_COMMAND,
    VM_EXTENSIONS_WRITE,
    GALLERY_APP_WRITE,
    AKS_RUN_COMMAND,
    VMSS_RUN_COMMAND,
    SERIAL_CONSOLE_CONNECT,
]


def rule(event):
    operation = event.get("operationName", "").upper()
    return all([operation in AZT301_OPERATIONS, azure_activity_success(event)])


# Map operations to (resource_type_key, display_name, technique_name)
OPERATION_METADATA = {
    VM_RUN_COMMAND: ("virtualMachines", "Virtual Machine", "RunCommand"),
    VM_EXTENSIONS_WRITE: ("virtualMachines", "VM Extension", "Extension"),
    GALLERY_APP_WRITE: ("applications", "Gallery Application", "Gallery Application"),
    AKS_RUN_COMMAND: ("managedClusters", "AKS Cluster", "AKS Command"),
    VMSS_RUN_COMMAND: ("virtualMachineScaleSets", "VM Scale Set", "VMSS RunCommand"),
    SERIAL_CONSOLE_CONNECT: ("virtualMachines", "Serial Console", "Serial Console"),
}


def title(event):
    resource_id = event.get("resourceId", "")
    operation = event.get("operationName", "").upper()

    if operation in OPERATION_METADATA:
        resource_type_key, _, technique = OPERATION_METADATA[operation]
        resource_name = extract_resource_name_from_id(
            resource_id, resource_type_key, default="<UNKNOWN_RESOURCE>"
        )
    else:
        technique = "Command"
        resource_name = "<UNKNOWN_RESOURCE>"

    return f"Azure VM {technique} Executed on [{resource_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    return context
