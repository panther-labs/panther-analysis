from panther_base_helpers import aws_rule_context


def rule(event):
    return all(
        [
            event.get("eventSource", "") == "rds.amazonaws.com",
            event.get("eventName", "") == "CreateDBSnapshot",
            event.deep_get("responseElements", "snapshotType") in {"manual", "public"},
        ]
    )


def title(event):
    account_id = event.get("recipientAccountId", "")
    rds_instance_id = event.deep_get("responseElements", "dBInstanceIdentifier")
    return f"Manual RDS Snapshot Created in [{account_id}] for RDS instance [{rds_instance_id}]"


def alert_context(event):
    return aws_rule_context(event)
