from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context

REMOTE_ACCESS_EXECUTABLES = {
    "teamviewer_service.exe",
    "winvnc.exe",
    "racwinvnc.exe",
    "tvnserver.exe",
    "ultravnc.exe",
    "remotelyanywhere.exe",
    "logmein.exe",
    "g2svc.exe",
    "vncserver.exe",
    "awhost32.exe",
    "r_server.exe",
    "raabout.exe",
    "anydesk.exe",
    "ammyyadmin.exe",
    "putty.exe",
    "mstsc.exe",
    "chrome-remote-desktop-host.exe",
}


def rule(event):
    if event.get("fdr_event_type", "") == "ProcessRollup2":
        if event.get("event_platform", "") == "Win":
            process_name = (
                event.deep_get("event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            return process_name in REMOTE_ACCESS_EXECUTABLES
    return False


def title(event):
    tool = (
        event.deep_get("event", "ImageFileName", default="<TOOL_NOT_FOUND>").lower().split("\\")[-1]
    )
    return f"Crowdstrike: Remote access tool [{tool}] detected"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
