def rule(event):
    return event.get("eventName") == "DisassociateWebACL"


def title(event):
    return (
        f"AWS Account ID [{event.get('recipientAccountId')}] "
        f"disassociated WebACL [{event.deep_get('requestParameters', 'resourceArn')}]"
    )


def alert_context(event):
    return {
        "awsRegion": event.get("awsRegion"),
        "eventName": event.get("eventName"),
        "recipientAccountId": event.get("recipientAccountId"),
        "requestID": event.get("requestID"),
        "actor_user": event.udm("actor_user"),
        "requestParameters": event.deep_get("requestParameters", "resourceArn"),
        "userIdentity": event.deep_get("userIdentity", "principalId"),
    }
