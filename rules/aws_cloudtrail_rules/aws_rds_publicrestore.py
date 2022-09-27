from panther_base_helpers import aws_rule_context, deep_get


def rule(event):
    if (
        event.get("eventSource", "") == "rds.amazonaws.com"
        and event.get("eventName", "") == "RestoreDBInstanceFromDBSnapshot"
    ):
        if deep_get(event, "responseElements", "publiclyAccessible"):
            return True
    return False


def title(event):
    return f"Publicly Accessible RDS restore created in [{event.get('recepientAccountId','')}]"


def alert_context(event):
    return aws_rule_context(event)
