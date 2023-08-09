from panther_base_helpers import crowdstrike_detection_alert_context, deep_get

SUSPICIOUS_PARENT_CHILD_COMBINATIONS_WINDOWS = {
    ("svchost.exe", "cmd.exe"),
    ("explorer.exe", "powershell.exe"),
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
            parent_process_name = deep_get(event, "event", "ParentBaseFileName", default="").lower()
            child_process_name = (
                deep_get(event, "event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            return (
                parent_process_name,
                child_process_name,
            ) in SUSPICIOUS_PARENT_CHILD_COMBINATIONS_WINDOWS
    return False


def title(event):
    parent_process_name = deep_get(event, "event", "ParentBaseFileName", default="").lower()
    child_process_name = (
        deep_get(event, "event", "ImageFileName", default="").lower().split("\\")[-1]
    )
    procs = (parent_process_name, child_process_name)
    aid = event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: Suspicious parent/child combination [{procs}] detected on aid [{aid}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
