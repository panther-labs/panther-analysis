from panther_base_helpers import deep_get

def rule(event):
    return event.get('eventName') == 'TerminateInstances'

def title(event):
    items = deep_get(event, 'requestParameters', 'instancesSet', 'items')
    return f" AWS Event [{event.get('eventName')}] Instance ID [{items[0].get('instanceId')}] AWS Account ID [{event.get('recipientAccountId')}]"

def alert_context(event):
    items = deep_get(event, 'requestParameters', 'instancesSet', 'items')
    return {
        "awsRegion": event.get('awsRegion'),
        "eventName": event.get('eventName'),
        "recipientAccountId": event.get('recipientAccountId'),
        "instanceId": items[0].get('instanceId')
    }
