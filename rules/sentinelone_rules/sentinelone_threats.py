from panther_base_helpers import deep_get

NEW_THREAT_ACTIVITYTYPES = [
    19,  # New Malicious Threat Not Mitigated
    4108,  # New Malicious Threat Not Mitigated
    4003,  # New Suspicious Threat Not Mitigated
    4109,  # New Suspicious Threat Not Mitigated
]


def rule(event):
    return event.get("activitytype") in NEW_THREAT_ACTIVITYTYPES


def title(event):
    return (
        f"SentinelOne - [{deep_get(event, 'data', 'confidencelevel', default='')}] level "
        f"[{deep_get(event, 'data', 'threatclassification' ,default='')}] threat detected from "
        f"[{deep_get(event, 'data', 'threatclassificationsource', default= '')}]."
    )


def dedup(event):
    return f"s1threat:{event.get('id','')}"


def severity(event):
    if deep_get(event, "data", "confidencelevel", default="") == "malicious":
        return "CRITICAL"
    else:
        return "HIGH"


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
