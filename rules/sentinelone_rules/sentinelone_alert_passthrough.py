from panther_base_helpers import deep_get

SENTINELONE_SEVERITY = {
    "E_LOW": "LOW",
    "E_MEDIUM": "MEDIUM",
    "E_HIGH": "HIGH",
    "E_CRITICAL": "CRITICAL",
}


def rule(event):
    # 3608 corresponds to new alerts
    return event.get("activitytype") == 3608


def title(event):
    return (
        "SentinelOne "
        f"[{SENTINELONE_SEVERITY.get(deep_get(event,'data', 'severity', default=''))}] "
        f"Alert - [{deep_get(event, 'data', 'rulename')}]"
    )


def dedup(event):
    return f"s1alerts:{event.get('id')}"


def severity(event):
    return SENTINELONE_SEVERITY.get(deep_get(event, "data", "severity", default=""), "MEDIUM")


def alert_context(event):
    data_cleaned = {k: v for k, v in event.get("data", {}).items() if v != ""}
    return {
        "primarydescription": event.get("primarydescription", ""),
        "accountname": event.get("accountname", ""),
        "accountid": event.get("accountid", ""),
        "siteid": event.get("siteid", ""),
        "sitename": event.get("sitename", ""),
        "groupid": event.get("groupid", ""),
        "groupname": event.get("groupname", ""),
        "activityuuid": event.get("activityuuid", ""),
        "agentid": event.get("agentid", ""),
        "id": event.get("id", ""),
        "data": data_cleaned,
    }
