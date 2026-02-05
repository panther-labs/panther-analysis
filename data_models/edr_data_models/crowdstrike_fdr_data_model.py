"""CrowdStrike FDR Data Model - includes Sigma field mappings
This data model provides both standard UDM mappings and Sigma field mappings
for CrowdStrike FDR events.
"""

from panther_base_helpers import deep_get


def get_dns_query(event):
    # Strip trailing period.
    # Domain Names from Crowdstrike FDR end with a trailing period, such as google.com.
    domain = deep_get(event, "event", "DomainName", default=None)
    if domain:
        domain = domain.rstrip(".")
    return domain


def get_process_name(event):
    platform = event.get("event_platform")
    # Extract process name from path
    # Win = \Device\HarddiskVolume2\Windows\System32\winlogon.exe
    # Lin = /usr/bin/run-parts
    # Mac = /usr/libexec/xpcproxy
    image_fn = deep_get(event, "event", "ImageFileName")
    if not image_fn:
        return None  # Explicitly return None if the key DNE
    if platform == "Win":
        return image_fn.split("\\")[-1]
    return image_fn.split("/")[-1]


def get_parent_process_name(event):
    """Extract parent process name from ParentBaseFileName"""
    platform = event.get("event_platform")
    parent_fn = deep_get(event, "event", "ParentBaseFileName", default=None)
    if not parent_fn:
        return None
    if platform == "Win":
        return parent_fn.split("\\")[-1]
    return parent_fn.split("/")[-1]


def get_event_category(event):
    """Normalize CrowdStrike event_simpleName to Sigma category"""
    event_simple_name = event.get("event_simpleName", "")

    # Process creation events
    if event_simple_name in ["ProcessRollup2", "SyntheticProcessRollup2"]:
        return "process_creation"

    # File events
    if event_simple_name == "FileOpenInfo":
        return "file_event"

    # DNS query events
    if event_simple_name == "DnsRequest":
        return "dns_query"

    # Network connection events
    if event_simple_name in [
        "NetworkConnectIP4",
        "NetworkConnectIP6",
        "NetworkReceiveAcceptIP4",
        "NetworkReceiveAcceptIP6",
    ]:
        return "network_connection"

    return None


def get_os(event):
    """Normalize CrowdStrike event_platform to standard OS name"""
    event_platform = event.get("event_platform", "")

    if event_platform == "Win":
        return "windows"
    if event_platform == "Linux":
        return "linux"
    if event_platform == "Mac":
        return "macos"

    return None
