from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

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


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    operation = event.get("operationName", "").upper()
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    # Determine the technique type
    if operation == VM_RUN_COMMAND:
        technique = "RunCommand"
        resource_name = _extract_vm_name(resource_id)
    elif operation == VM_EXTENSIONS_WRITE:
        technique = "Extension"
        resource_name = _extract_vm_name(resource_id)
    elif operation == GALLERY_APP_WRITE:
        technique = "Gallery Application"
        resource_name = _extract_gallery_app(resource_id)
    elif operation == AKS_RUN_COMMAND:
        technique = "AKS Command"
        resource_name = _extract_aks_cluster(resource_id)
    elif operation == VMSS_RUN_COMMAND:
        technique = "VMSS RunCommand"
        resource_name = _extract_vmss_name(resource_id)
    elif operation == SERIAL_CONSOLE_CONNECT:
        technique = "Serial Console"
        resource_name = _extract_vm_name(resource_id)
    else:
        technique = "Command"
        resource_name = "<UNKNOWN_RESOURCE>"

    return f"Azure VM {technique} Executed on [{resource_name}] from [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    operation = event.get("operationName", "").upper()
    resource_id = event.get("resourceId", "")

    # Add operation-specific context
    context["execution_method"] = _get_execution_method(operation)

    if operation == VM_RUN_COMMAND:
        context["resource_name"] = _extract_vm_name(resource_id)
        context["resource_type"] = "Virtual Machine"
    elif operation == VM_EXTENSIONS_WRITE:
        context["resource_name"] = _extract_vm_name(resource_id)
        context["resource_type"] = "VM Extension"
        context["extension_name"] = _extract_extension_name(resource_id)
    elif operation == GALLERY_APP_WRITE:
        context["resource_name"] = _extract_gallery_app(resource_id)
        context["resource_type"] = "Gallery Application"
    elif operation == AKS_RUN_COMMAND:
        context["resource_name"] = _extract_aks_cluster(resource_id)
        context["resource_type"] = "AKS Cluster"
    elif operation == VMSS_RUN_COMMAND:
        context["resource_name"] = _extract_vmss_name(resource_id)
        context["resource_type"] = "VM Scale Set"
    elif operation == SERIAL_CONSOLE_CONNECT:
        context["resource_name"] = _extract_vm_name(resource_id)
        context["resource_type"] = "Serial Console"

    return context


def _extract_vm_name(resource_id):
    """Extract VM name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_VM>"
    parts = resource_id.split("/")
    if "virtualMachines" in parts:
        try:
            return parts[parts.index("virtualMachines") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_VM>"


def _extract_extension_name(resource_id):
    """Extract extension name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_EXTENSION>"
    parts = resource_id.split("/")
    if "extensions" in parts:
        try:
            return parts[parts.index("extensions") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_EXTENSION>"


def _extract_gallery_app(resource_id):
    """Extract gallery application name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_APP>"
    parts = resource_id.split("/")
    if "applications" in parts:
        try:
            return parts[parts.index("applications") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_APP>"


def _extract_aks_cluster(resource_id):
    """Extract AKS cluster name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_CLUSTER>"
    parts = resource_id.split("/")
    if "managedClusters" in parts:
        try:
            return parts[parts.index("managedClusters") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_CLUSTER>"


def _extract_vmss_name(resource_id):
    """Extract VMSS name from resource ID"""
    if not resource_id:
        return "<UNKNOWN_VMSS>"
    parts = resource_id.split("/")
    if "virtualMachineScaleSets" in parts:
        try:
            return parts[parts.index("virtualMachineScaleSets") + 1]
        except (IndexError, ValueError):
            pass
    return "<UNKNOWN_VMSS>"


def _get_execution_method(operation):
    """Map operation to AZT301 sub-technique"""
    mapping = {
        VM_RUN_COMMAND: "AZT301.1 - RunCommand",
        VM_EXTENSIONS_WRITE: "AZT301.2/AZT301.3 - CustomScriptExtension/DSC",
        GALLERY_APP_WRITE: "AZT301.4 - Compute Gallery Application",
        AKS_RUN_COMMAND: "AZT301.5 - AKS Command Invoke",
        VMSS_RUN_COMMAND: "AZT301.6 - VMSS Run Command",
        SERIAL_CONSOLE_CONNECT: "AZT301.7 - Serial Console",
    }
    return mapping.get(operation, "Unknown")
