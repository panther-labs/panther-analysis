def rule(event):
    # Only look for successes
    if event.get('errorCode') or event.get('errorMessage'):
        return False
    # Reference: https://awsteele.com/blog/2020/09/26/aws-access-key-format.html
    return event.deep_get('userIdentity', 'accessKeyId').startswith('AKIA')

def title(event):
    return f'User {event.deep_get("userIdentity", "arn")} authenticated in with access key {event.deep_get("userIdentity", "accessKeyId")}'

def alert_context(event):
    return {'ip_accessKeyId': event.get("sourceIpAddress") + ":" + event.deep_get("userIdentity", "accessKeyId")}