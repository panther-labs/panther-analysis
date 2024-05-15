from panther_base_helpers import aws_rule_context


def rule(event):
    if (
        event.udm("event_source", default="") == "rds.amazonaws.com"
        and event.udm("event_name", default="") == "RestoreDBInstanceFromDBSnapshot"
    ):
        if event.udm("publicly_accessible"):
            return True
    return False


def title(event):
    return f"Publicly Accessible RDS restore created in [{event.udm('recipient_account_id', default='')}]"


def alert_context(event):
    return aws_rule_context(event)
