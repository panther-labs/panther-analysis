from panther_base_helpers import aws_rule_context

# Account IDs exempted from this rule
ALLOWED_ACCOUNTS = {}


def rule(event):
    if all(
        [
            event.get("eventSource", "") == "rds.amazonaws.com",
            event.get("eventName", "") == "ModifyDBSnapshotAttribute"
            or event.get("eventName", "") == "ModifyDBClusterSnapshotAttribute",
            event.deep_get("requestParameters", "attributeName") == "restore",
        ]
    ):
        shared_account_ids = event.deep_get("requestParameters", "valuesToAdd", default=[])
        if shared_account_ids:
            return any(
                account_id
                for account_id in shared_account_ids
                if account_id not in ALLOWED_ACCOUNTS
            )
        return False
    return False


def title(event):
    account_id = event.get("recipientAccountId", default="<ACCOUNT_ID_NOT_FOUND>")
    rds_instance_id = event.deep_get(
        "responseElements", "dBInstanceIdentifier", default="<DB_INSTANCE_ID_NOT_FOUND>"
    )
    return f"RDS Snapshot Shared in [{account_id}] for RDS instance [{rds_instance_id}]"


def alert_context(event):
    return aws_rule_context(event)
