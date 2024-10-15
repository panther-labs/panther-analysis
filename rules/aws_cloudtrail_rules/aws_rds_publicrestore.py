from panther_base_helpers import aws_rule_context


def rule(event):
    if (
        event.get("eventSource", "") == "rds.amazonaws.com"
        and event.get("eventName", "") == "RestoreDBInstanceFromDBSnapshot"
    ):
        if event.deep_get("responseElements", "publiclyAccessible"):
            return True
    return False


def title(event):
    return f"Publicly Accessible RDS restore created in [{event.get('recipientAccountId','')}]"


def alert_context(event):
    return aws_rule_context(event)
