def rule(event):
    # Only look for successes
    if event.get("errorCode") or event.get("errorMessage"):
        return False
    # Reference: https://awsteele.com/blog/2020/09/26/aws-access-key-format.html
    return event.deep_get("userIdentity", "accessKeyId").startswith("AKIA")


def title(event):
    arn = event.deep_get("userIdentity", "arn")
    key = event.deep_get("userIdentity", "accessKeyId")
    return f"User {arn} signed in with access key {key}"


def alert_context(event):
    return {
        "ip_accessKeyId": event.get("sourceIpAddress")
        + ":"
        + event.deep_get("userIdentity", "accessKeyId")
    }
