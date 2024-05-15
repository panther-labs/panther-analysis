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
    return event.udm("event_name") in MACIE_EVENTS and pattern_match(
        event.udm("event_source"), "macie*.amazonaws.com"
    )


def title(event):
    account = event.udm("recipient_account_id")
    user_arn = event.udm("user_arn")
    return f"AWS Macie in AWS Account [{account}] Disabled/Updated by [{user_arn}]"
