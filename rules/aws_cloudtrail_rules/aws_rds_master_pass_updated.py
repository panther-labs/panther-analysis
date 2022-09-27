from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("eventName") == "ModifyDBInstance"
        and event.get("eventSource") == "rds.amazonaws.com"
        and bool(deep_get(event, "responseElements", "pendingModifiedValues", "masterUserPassword"))
    )


def title(event):
    return (
        f"RDS Master Password Updated on [{deep_get(event, 'responseElements', 'dBInstanceArn')}]"
    )
