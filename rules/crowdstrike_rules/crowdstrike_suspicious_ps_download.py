from panther_base_helpers import (
    crowdstrike_detection_alert_context,
    deep_get,
    pattern_match_list,
)

PS_CMDS = {"Invoke-WebRequest", "Net.WebClient", "Start-BitsTransfer"}


def rule(event):

    # Check for the powershell commands being called that relate to file transfer and downloads
    if (
        event.get("event_simpleName") == "ProcessRollup2"
        and deep_get(event, "event", "FileName", default="") == "powershell.exe"
        and pattern_match_list(deep_get(event, "event", "CommandLine", default=""), PS_CMDS)
    ):
        return True
    return False


def title(event):
    return (
        f"Suspicious PowerShell download from "
        "{deep_get(event, 'event', 'FileName')} - {deep_get(event, 'event', 'CommandLine')}"
    )


def alert_context(event):
    return crowdstrike_detection_alert_context
