from panther_base_helpers import aws_rule_context


def rule(event):
    return all(
        [
            event.udm("event_source") == "rds.amazonaws.com",
            event.udm("event_name") == "CreateDBSnapshot",
            event.udm("snapshot_type") in {"manual", "public"},
        ]
    )


def title(event):
    account_id = event.udm("recipient_account_id", default="")
    rds_instance_id = event.udm("db_instance_identifier")
    return f"Manual RDS Snapshot Created in [{account_id}] for RDS instance [{rds_instance_id}]"


def alert_context(event):
    return aws_rule_context(event)
