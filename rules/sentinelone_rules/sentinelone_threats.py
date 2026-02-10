NEW_THREAT_ACTIVITYTYPES = [
    # Malicious Threats - Not Mitigated
    19,  # New Malicious Threat Not Mitigated
    4108,  # New Malicious Threat Not Mitigated (detected by SentinelOne Cloud)
    # Suspicious Threats - Not Mitigated
    4003,  # New Suspicious Threat Not Mitigated
    4109,  # New Suspicious Threat Not Mitigated (detected by SentinelOne Cloud)
    # New Threats - Mitigated/Blocked
    18,  # New Threat Mitigated
    20,  # New Threat Preemptive Block
    # Automated Threat Intelligence Detections
    4106,  # STAR Active Response Marked Event As Malicious
    4107,  # STAR Active Response Marked Event As Suspicious
    4110,  # Singularity Threat Intelligence Engine Marked Event As Malicious
    4111,  # Watchtower Cloud Detection Engine Marked Event As Threat
    4112,  # Watchtower Cloud Detection Engine Marked Event As Suspicious
    4113,  # Singularity Threat Intelligence Engine Marked Event As Suspicious
]


def rule(event):
    return event.get("activitytype") in NEW_THREAT_ACTIVITYTYPES


def title(event):
    return (
        f"SentinelOne - [{event.deep_get('data', 'confidencelevel', default='')}] level threat "
        f"[{event.deep_get('data', 'filedisplayname', default='NO FILE NAME')}] detected on "
        f"[{event.deep_get('data', 'computername', default='NO COMPUTER NAME')}]."
    )


def dedup(event):
    return f"s1threat:{event.get('id', '')}"


def severity(event):
    if event.deep_get("data", "confidencelevel", default="") == "malicious":
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return {
        "primarydescription": event.get("primarydescription", ""),
        "accountname": event.get("accountname", ""),
        "accountid": event.get("accountid", ""),
        "siteid": event.get("siteid", ""),
        "sitename": event.get("sitename", ""),
        "threatid": event.get("threatid", ""),
        "groupid": event.get("groupid", ""),
        "groupname": event.get("groupname", ""),
        "activityuuid": event.get("activityuuid", ""),
        "agentid": event.get("agentid", ""),
        "id": event.get("id", ""),
        "data": event.get("data", {}),
    }
