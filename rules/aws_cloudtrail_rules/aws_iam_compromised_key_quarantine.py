IAM_ACTIONS = {
    "AttachUserPolicy",
    "AttachGroupPolicy",
    "AttachRolePolicy",
}

QUARANTINE_MANAGED_POLICY = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2"


def rule(event):
    return all(
        [
            event.udm("event_source", default="") == "iam.amazonaws.com",
            event.udm("event_name", default="") in IAM_ACTIONS,
            event.udm("policy_arn", default="") == QUARANTINE_MANAGED_POLICY,
        ]
    )


def title(event):
    account_id = event.udm("recipient_account_id", default="<ACCOUNT_ID_NOT_FOUND>")
    user_name = event.udm("user_name", default="<USER_NAME_NOT_FOUND>")
    return f"Compromised Key quarantined for [{user_name}] in AWS Account [{account_id}]"
