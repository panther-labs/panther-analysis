from panther_base_helpers import deep_get


def rule(event):
    return deep_get(event, "unknown_payload", "ExternalApiType") == "Event_RemoteResponseSessionStartEvent"


def title(event):
    user_name = deep_get(event, "unknown_payload", "UserName")
    hostname_field = deep_get(event, "unknown_payload", "HostnameField")
    return f"{user_name} started a Crowdstrike Real-Time Response (RTR) shell on {hostname_field}"


def alert_context(event):
    return {
        "Start Time": deep_get(event, "unknown_payload", "StartTimestamp"),
        "SessionId": deep_get(event, "unknown_payload", "SessionId"),
        "Actor": deep_get(event, "unknown_payload", "UserName"),
        "Target Host": deep_get(event, "unknown_payload", "HostnameField"),
    }
