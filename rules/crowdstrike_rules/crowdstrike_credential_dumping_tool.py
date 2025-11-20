from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context

CREDENTIAL_DUMPING_TOOLS = {
    "mimikatz.exe",
    "secretsdump.py",
    "pwdump.exe",
    "fgdump.exe",
    "gsecdump.exe",
    "samdump2.exe",
    "quarks-pwdump.exe",
    "cachedump.exe",
    "lsadump.exe",
    "procdump.exe",
    "mimipenguin.sh",
    "mimidogz.ps1",
    "logonpasswords.exe",
    "pypykatz.exe",
    "dsusers.py",
    "ntdsgrab.py",
    "lazagne.exe",
    "creddump7.exe",
    "keethief.ps1",
    "inveigh.exe",
    "sharpkatz.exe",
    "dumpert.exe",
    "hivedump.exe",
    "kerbrute.exe",
    "sessiongopher.ps1",
}


def rule(event):
    if event.get("fdr_event_type", "") == "ProcessRollup2":
        if event.get("event_platform", "") == "Win":
            process_name = (
                event.deep_get("event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            if process_name in CREDENTIAL_DUMPING_TOOLS:
                return True
    return False


def title(event):
    tool = (
        event.deep_get("event", "ImageFileName", default="<TOOL_NOT_FOUND>").lower().split("\\")[-1]
    )
    host = event.get("ComputerName") or event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: Credential dumping tool [{tool}] detected on host [{host}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
