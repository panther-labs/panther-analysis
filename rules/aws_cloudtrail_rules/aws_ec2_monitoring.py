from panther_base_helpers import deep_get

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
    if event.get("eventSource", "") != "ec2.amazonaws.com":
        return False
    # Disqualify AWS Service-Service operations, which can appear in a variety of forms
    if (
        # FYI there is a weird quirk in the sourceIPAddress field of CloudTrail
        #  events with ec2.amazonaws.com as the source name where users of the
        #  web-console will have their sourceIPAddress recorded as "AWS Internal"
        #  though their userIdentity will be more normal.
        #  Example cloudtrail event in the "Terminate instance From WebUI with assumedRole" test
        event.get("sourceIPAddress", "").endswith(".amazonaws.com")
        or deep_get(event, "userIdentity", "type", default="") == "AWSService"
        or deep_get(event, "userIdentity", "invokedBy", default="") == "AWS Internal"
        or deep_get(event, "userIdentity", "invokedBy", default="").endswith(".amazonaws.com")
    ):
        return False
    # Dry run operations get logged as SES Internal in the sourceIPAddress
    #  but not in the invokedBy field
    if event.get("errorCode", "") == "Client.DryRunOperation":
        return False
    # Disqualify any eventNames that do not Include Image Actions
    # and events that have readOnly set to false
    if event.get("eventName", "") in EC2_IMAGE_ACTIONS:
        return True

    return False


def title(event):
    return (
        f"[{deep_get(event, 'userIdentity', 'sessionContext', 'sessionIssuer', 'userName')}] "
        f"triggered a CloudTrail action [{event.get('eventName')}] "
        f"within AWS Account ID: [{event.get('recipientAccountId')}]"
    )
