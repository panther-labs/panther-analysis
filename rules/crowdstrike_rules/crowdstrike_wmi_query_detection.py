from panther_base_helpers import crowdstrike_detection_alert_context, deep_get

WMIC_SIGNATURES = ["get", "list", "process call create", "cmd.exe", "powershell.exe", "command.exe"]


def rule(event):
    if deep_get(event, "event", "event_simpleName") == "ProcessRollup2":
        if deep_get(event, "event", "event_platform") == "Win":
            if deep_get(event, "event", "ImageFileName", default="").split("\\")[-1] == "wmic.exe":
                command_line = deep_get(event, "event", "CommandLine", default="")
                for signature in WMIC_SIGNATURES:
                    if signature in command_line:
                        return True
    return False


def title(event):
    cmd = deep_get(event, "event", "CommandLine", default="<COMMAND_LINE_NOT_FOUND>")
    aid = event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: WMIC Query [{cmd}] performed on aid [{aid}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
