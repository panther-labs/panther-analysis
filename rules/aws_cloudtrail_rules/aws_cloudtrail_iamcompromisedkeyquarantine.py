IAM_ACTIONS = {
    "AttachUserPolicy",
    "AttachGroupPolicy",
    "AttachRolePolicy",
}

QUARANTINE_MANAGED_POLICY = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2"


def rule(event):
    return all(
        [
            event.get("eventSource", "") == "iam.amazonaws.com",
            event.get("eventName", "") in IAM_ACTIONS,
            event.deep_get("requestParameters", "policyArn", default="")
            == QUARANTINE_MANAGED_POLICY,
        ]
    )


def title(event):
    account_id = event.deep_get("recipientAccountId", default="<ACCOUNT_ID_NOT_FOUND>")
    user_name = event.deep_get("requestParameters", "userName", default="<USER_NAME_NOT_FOUND>")
    return f"Compromised Key quarantined for [{user_name}] in AWS Account [{account_id}]"
