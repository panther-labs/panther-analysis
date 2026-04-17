def rule(event):
    return (
        event.get("eventName") == "ModifyDBInstance"
        and event.get("eventSource") == "rds.amazonaws.com"
        and bool(event.deep_get("responseElements", "pendingModifiedValues", "masterUserPassword"))
    )


def title(event):
    return f"RDS Master Password Updated on [{event.deep_get('responseElements', 'dBInstanceArn')}]"
