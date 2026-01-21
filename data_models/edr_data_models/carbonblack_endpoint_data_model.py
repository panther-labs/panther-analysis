"""Carbon Black Endpoint Event Data Model - Sigma field mappings
This data model maps Sigma fields to Carbon Black EndpointEvent fields.
Based on field mappings from pySigma-backend-panther.
"""


def get_process_name(event):
    """Extract process name from full path"""
    process_path = event.get("process_path", "")
    if not process_path:
        return None
    # Handle both Windows and Unix paths
    if "\\" in process_path:
        return process_path.split("\\")[-1]
    return process_path.split("/")[-1]


def get_parent_process_name(event):
    """Extract parent process name from full path"""
    parent_path = event.get("parent_path", "")
    if not parent_path:
        return None
    # Handle both Windows and Unix paths
    if "\\" in parent_path:
        return parent_path.split("\\")[-1]
    return parent_path.split("/")[-1]


def get_event_category(event):
    """Normalize Carbon Black event type to Sigma category"""
    event_type = event.get("type", "")

    # Process creation events
    if event_type == "endpoint.event.procstart":
        return "process_creation"

    # File modification events
    if event_type == "endpoint.event.filemod":
        return "file_event"

    # Network connection events
    if event_type == "endpoint.event.netconn":
        return "network_connection"

    return None


def get_os(event):
    """Normalize Carbon Black device_os to standard OS name"""
    device_os = event.get("device_os", "")

    if device_os == "WINDOWS":
        return "windows"
    if device_os == "LINUX":
        return "linux"
    if device_os == "MAC":
        return "macos"

    return None
