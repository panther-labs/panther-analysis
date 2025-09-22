from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context

CRYPTOCURRENCY_MINING_TOOLS = {
    "xmrig.exe",
    "cgminer.exe",
    "bfgminer.exe",
    "ethminer.exe",
    "minergate-cli.exe",
    "nicehashminer.exe",
    "sgminer.exe",
    "cpuminer.exe",
    "cudaminer.exe",
    "nheqminer.exe",
    "claymore.exe",
    "xmr-stak.exe",
    "ccminer.exe",
    "zecminer64.exe",
    "ewbf.exe",
    "nanominer.exe",
    "phoenixminer.exe",
    "t-rex.exe",
    "gminer.exe",
    "lolminer.exe",
    "teamredminer.exe",
    "nbminer.exe",
    "daggerhashimoto.exe",
}


def rule(event):
    if event.get("fdr_event_type", "") == "ProcessRollup2":
        if event.get("event_platform", "") == "Win":
            process_name = (
                event.deep_get("event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            return process_name in CRYPTOCURRENCY_MINING_TOOLS
    return False


def title(event):
    tool = (
        event.deep_get("event", "ImageFileName", default="<TOOL_NOT_FOUND>").lower().split("\\")[-1]
    )
    host = event.get("ComputerName") or event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: Cryptocurrency mining tool [{tool}] detected on host [{host}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
