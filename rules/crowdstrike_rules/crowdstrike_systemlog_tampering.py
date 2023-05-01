from panther_base_helpers import crowdstrike_detection_alert_context, deep_get

CLEARING_SYSTEM_LOG_TOOLS = {
    "wevtutil.exe": ["cl", "clear-log"],
    "powershell.exe": ["clear-eventlog"],
}


def rule(event):
    if event.get("fdr_event_type", "") == "ProcessRollup2":
        if event.get("event_platform", "") == "Win":
            process_name = (
                deep_get(event, "event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            if process_name in CLEARING_SYSTEM_LOG_TOOLS:
                process_command_line = deep_get(event, "event", "CommandLine", default="").split(
                    " "
                )
                suspicious_command_lines = CLEARING_SYSTEM_LOG_TOOLS.get(process_name)
                for suspicious_command_line in suspicious_command_lines:
                    if suspicious_command_line in process_command_line:
                        return True
    return False


def title(event):
    aid = event.get("aid", "<AID_NOT_FOUND>")
    command = deep_get(event, "event", "CommandLine", default="<COMMAND_NOT_FOUND>")
    return (
        "Crowdstrike: System log tampering attempt detected on "
        f"aid [{aid}] with command [{command}]"
    )


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
