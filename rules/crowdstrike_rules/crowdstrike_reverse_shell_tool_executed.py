from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context

REMOTE_SHELL_TOOLS = {
    #   process name: reverse shell signature
    "nc.exe": ["cmd.exe", "powershell.exe", "command.exe"],
    "ncat.exe": ["cmd.exe", "powershell.exe", "command.exe"],
    "socat.exe": ["cmd.exe", "powershell.exe", "command.exe"],
    "psexec.exe": ["cmd.exe", "powershell.exe", "command.exe"],
    "python.exe": ["cmd.exe", "powershell.exe", "command.exe"],
    "powershell.exe": ["System.Net.Sockets.TcpClient"],
    "certutil.exe": ["-urlcache"],
    "php.exe": ["fsockopen", "cmd.exe", "powershell.exe", "command.exe"],
}


def rule(event):
    if event.get("fdr_event_type", "") == "ProcessRollup2":
        if event.get("event_platform", "") == "Win":
            process_name = (
                event.deep_get("event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            command_line = event.deep_get("event", "CommandLine", default="")
            signatures = REMOTE_SHELL_TOOLS.get(process_name, [])
            for signature in signatures:
                if signature in command_line:
                    return True
    return False


def title(event):
    tool = (
        event.deep_get("event", "ImageFileName", default="<TOOL_NOT_FOUND>").lower().split("\\")[-1]
    )
    host = event.get("ComputerName") or event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: Reverse shell tool [{tool}] detected on host [{host}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
