from panther_base_helpers import pattern_match

MACIE_EVENTS = {
    "ArchiveFindings",
    "CreateFindingsFilter",
    "DeleteMember",
    "DisassociateFromMasterAccount",
    "DisassociateMember",
    "DisableMacie",
    "DisableOrganizationAdminAccount",
    "UpdateFindingsFilter",
    "UpdateMacieSession",
    "UpdateMemberSession",
    "UpdateClassificationJob",
}


def rule(event):
    return event.get("eventName") in MACIE_EVENTS and pattern_match(
        event.get("eventSource"), "macie*.amazonaws.com"
    )


def runbook(event):
    user_arn = event.deep_get("userIdentity", "arn", "arn-not-found")
    aws_account = event.deep_get("recipientAccountId", "account-not-found")
    return (
        f"Macie is managed by Terraform. If it's disabled by an IAM user, this is likely a "
        f"malicious insider. Check all aws_cloudtrail logs for the user [{user_arn}] in the "
        f"hour around this alert and look for other security services accessed/changed in "
        f"AWS account [{aws_account}]."
    )


def title(event):
    account = event.get("recipientAccountId")
    user_arn = event.deep_get("userIdentity", "arn")
    region = event.deep_get("awsRegion")
    return f"AWS Macie in AWS Account [{account}]-[{region}] was disabled/updated by [{user_arn}]"
