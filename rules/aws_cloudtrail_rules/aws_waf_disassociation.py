def rule(event):
    return event.udm("event_name") == "DisassociateWebACL"


def title(event):
    return (
        f"AWS Account ID [{event.udm('recipient_account_id')}] "
        f"disassociated WebACL [{event.udm('resource_arn')}]"
    )


def alert_context(event):
    return {
        "awsRegion": event.udm("cloud_region"),
        "eventName": event.udm("event_name"),
        "recipientAccountId": event.udm("recipient_account_id"),
        "requestID": event.get("requestID"),
        "requestParameters": event.udm("resource_arn"),
        "userIdentity": event.udm("user_principal_id"),
    }
