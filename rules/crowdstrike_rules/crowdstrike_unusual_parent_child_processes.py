from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context

SUSPICIOUS_PARENT_CHILD_COMBINATIONS_WINDOWS = {
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
}


def rule(event):
    if event.get("fdr_event_type", "") == "ProcessRollup2":
        if event.get("event_platform", "") == "Win":
            parent_process_name = event.deep_get("event", "ParentBaseFileName", default="").lower()
            child_process_name = (
                event.deep_get("event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            return (
                parent_process_name,
                child_process_name,
            ) in SUSPICIOUS_PARENT_CHILD_COMBINATIONS_WINDOWS
    return False


def title(event):
    parent_process_name = event.deep_get("event", "ParentBaseFileName", default="").lower()
    child_process_name = (
        event.deep_get("event", "ImageFileName", default="").lower().split("\\")[-1]
    )
    procs = (parent_process_name, child_process_name)
    return f"Crowdstrike: Suspicious parent/child combination [{procs}] detected"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
