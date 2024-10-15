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


def title(event):
    account = event.get("recipientAccountId")
    user_arn = event.deep_get("userIdentity", "arn")
    return f"AWS Macie in AWS Account [{account}] Disabled/Updated by [{user_arn}]"
