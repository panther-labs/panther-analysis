from panther_base_helpers import deep_get


def rule(event):
    master_user_pass = deep_get(
        event, "responseElements", "pendingModifiedValues", "masterUserPassword"
    )
    return (
        event.get("eventName") == "ModifyDBInstance"
        and event.get("eventSource") == "rds.amazonaws.com"
        and bool(master_user_pass)
    )


def title(event):
    return (
        f"RDS Master Password Updated on [{deep_get(event, 'responseElements', 'dBInstanceArn')}]"
    )
