from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context

WMIC_SIGNATURES = ["get", "list", "process call create", "cmd.exe", "powershell.exe", "command.exe"]


def rule(event):
    if event.deep_get("event", "event_simpleName") == "ProcessRollup2":
        if event.deep_get("event", "event_platform") == "Win":
            if event.deep_get("event", "ImageFileName", default="").split("\\")[-1] == "wmic.exe":
                command_line = event.deep_get("event", "CommandLine", default="")
                for signature in WMIC_SIGNATURES:
                    if signature in command_line:
                        return True
    return False


def title(event):
    cmd = event.deep_get("event", "CommandLine", default="<COMMAND_LINE_NOT_FOUND>")
    host = event.get("ComputerName") or event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: WMIC Query [{cmd}] performed on host [{host}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
