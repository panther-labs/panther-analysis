from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

PACKET_CAPTURE_OPERATIONS = [
    "MICROSOFT.NETWORK/NETWORKWATCHERS/STARTPACKETCAPTURE/ACTION",
    "MICROSOFT.NETWORK/NETWORKWATCHERS/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION",
    "MICROSOFT.NETWORK/NETWORKWATCHERS/PACKETCAPTURES/WRITE",
]


def rule(event):
    operation_name = event.get("operationName", "").upper()

    return any(
        pattern in operation_name for pattern in PACKET_CAPTURE_OPERATIONS
    ) and azure_activity_success(event)


def title(event):
    location = event.get("location", "<UNKNOWN_LOCATION>")

    return f"Azure Network Packet Capture Enabled in [{location}]"


def alert_context(event):
    return azure_activity_alert_context(event)
