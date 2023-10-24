from panther_base_helpers import deep_get


def rule(event):
    return event.get("eventName") == "DisassociateWebACL"


def title(event):
    return (
        f"AWS Account ID [{event.get('recipientAccountId')}] "
        f"disassociated WebACL [{deep_get(event, 'requestParameters', 'resourceArn')}]"
    )


def alert_context(event):
    return {
        "awsRegion": event.get("awsRegion"),
        "eventName": event.get("eventName"),
        "recipientAccountId": event.get("recipientAccountId"),
        "requestID": event.get("requestID"),
        "requestParameters": deep_get(event, "requestParameters", "resourceArn"),
        "userIdentity": deep_get(event, "userIdentity", "principalId"),
    }
