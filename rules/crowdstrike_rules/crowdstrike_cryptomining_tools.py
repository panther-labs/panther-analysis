from panther_base_helpers import crowdstrike_detection_alert_context, deep_get

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
                deep_get(event, "event", "ImageFileName", default="").lower().split("\\")[-1]
            )
            return process_name in CRYPTOCURRENCY_MINING_TOOLS
    return False


def title(event):
    tool = (
        deep_get(event, "event", "ImageFileName", default="<TOOL_NOT_FOUND>")
        .lower()
        .split("\\")[-1]
    )
    aid = event.get("aid", "<AID_NOT_FOUND>")
    return f"Crowdstrike: Cryptocurrency mining tool [{tool}] detected on aid [{aid}]"


def alert_context(event):
    return crowdstrike_detection_alert_context(event)
