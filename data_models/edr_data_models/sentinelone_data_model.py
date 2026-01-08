"""SentinelOne Data Model - Sigma field mappings
This data model maps Sigma fields to SentinelOne Deep Visibility fields.
Based on field mappings from pySigma-backend-panther.
"""

from panther_base_helpers import deep_get


def get_destination_hostname(event):
    """Get destination hostname from url_address or event_dns_request"""
    url_address = deep_get(event, "url_address", default=None)
    if url_address:
        return url_address
    return deep_get(event, "event_dns_request", default=None)


def get_process_name(event):
    """Extract process name from tgt_process_image_path"""
    image_path = event.get("tgt_process_image_path", "")
    if not image_path:
        return None
    # Handle both Windows and Unix paths
    if "\\" in image_path:
        return image_path.split("\\")[-1]
    return image_path.split("/")[-1]


def get_parent_process_name(event):
    """Extract parent process name from src_process_image_path"""
    parent_path = event.get("src_process_image_path", "")
    if not parent_path:
        return None
    # Handle both Windows and Unix paths
    if "\\" in parent_path:
        return parent_path.split("\\")[-1]
    return parent_path.split("/")[-1]


def get_event_category(event):
    # pylint: disable=too-many-return-statements
    """Normalize SentinelOne EventType and ObjectType to Sigma category"""
    event_type = event.get("EventType", "")
    object_type = event.get("ObjectType", "")

    # Map EventType values
    if event_type == "Process Creation":
        return "process_creation"
    if event_type == "ModuleLoad":
        return "image_load"
    if event_type == "Named Pipe Creation":
        return "pipe_creation"
    if event_type in ["File Modification", "File Rename", "File Delete"]:
        return "file_event"

    # Map ObjectType values
    if object_type == "File":
        return "file_event"
    if object_type == "Registry":
        return "registry_event"
    if object_type == "DNS":
        return "dns_query"
    if object_type in ["DNS", "Url", "IP"]:
        return "network_connection"

    return None


def get_os(event):
    """Normalize SentinelOne EndpointOS to standard OS name"""
    endpoint_os = event.get("EndpointOS", "").lower()

    if endpoint_os == "windows":
        return "windows"
    if endpoint_os == "linux":
        return "linux"
    if endpoint_os == "osx":
        return "macos"

    return None
