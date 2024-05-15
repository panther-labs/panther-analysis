# AWS CloudTrail API eventNames for EC2 Image Actions
EC2_IMAGE_ACTIONS = [
    "CopyFpgaImage",
    "CopyImage",
    "CreateFpgaImage",
    "CreateImage",
    "CreateRestoreImageTask",
    "CreateStoreImageTask",
    "ImportImage",
]


def rule(event):
    # Disqualify any eventSource that is not ec2
    if event.udm("event_source") != "ec2.amazonaws.com":
        return False
    # Disqualify AWS Service-Service operations, which can appear in a variety of forms
    invoked_by = event.udm("invoked_by") or ""
    if (
        # FYI there is a weird quirk in the sourceIPAddress field of CloudTrail
        #  events with ec2.amazonaws.com as the source name where users of the
        #  web-console will have their sourceIPAddress recorded as "AWS Internal"
        #  though their userIdentity will be more normal.
        #  Example cloudtrail event in the "Terminate instance From WebUI with assumedRole" test
        event.udm("source_ip_address", default="").endswith(".amazonaws.com")
        or event.udm("user_type") == "AWSService"
        or invoked_by == "AWS Internal"
        or invoked_by.endswith(".amazonaws.com")
    ):
        return False
    # Dry run operations get logged as SES Internal in the sourceIPAddress
    #  but not in the invokedBy field
    if event.udm("error_code") == "Client.DryRunOperation":
        return False
    # Disqualify any eventNames that do not Include Image Actions
    # and events that have readOnly set to false
    if event.udm("event_name", default="") in EC2_IMAGE_ACTIONS:
        return True

    return False


def title(event):
    return (
        f"User [{event.udm('session_issuer_arn')}] "
        f"triggered a CloudTrail action [{event.udm('event_name')}] "
        f"within AWS Account ID: [{event.udm('recipient_account_id')}]"
    )
