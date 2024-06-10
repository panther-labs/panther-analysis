from panther_base_helpers import aws_rule_context


def rule(event):
    if all(
        [
            event.udm("event_source", default="") == "rds.amazonaws.com",
            event.udm("event_name", default="") == "ModifyDBSnapshotAttribute"
            or event.udm("event_name", default="") == "ModifyDBClusterSnapshotAttribute",
            event.udm("attribute_name") == "restore",
        ]
    ):
        current_account_id = event.udm("user_account_id", default="")
        shared_account_ids = event.udm("values_to_add", default=[])
        if shared_account_ids:
            return any(
                account_id for account_id in shared_account_ids if account_id != current_account_id
            )
        return False
    return False


def title(event):
    account_id = event.udm("recipient_account_id", default="<ACCOUNT_ID_NOT_FOUND>")
    rds_instance_id = event.udm("db_instance_identifier", default="<DB_INSTANCE_ID_NOT_FOUND>")
    return f"RDS Snapshot Shared in [{account_id}] for RDS instance [{rds_instance_id}]"


def alert_context(event):
    return aws_rule_context(event)
