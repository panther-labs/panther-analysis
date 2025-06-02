from panther_gcp_helpers import gcp_alert_context

def rule(event):
    # This is a correlation rule that will be triggered by the Panther platform
    # when all three conditions are met within the specified timeframe
    return True

def title(event):
    return f"GCP Privilege Escalation via TagBinding by {event.deep_get('protoPayload', 'authenticationInfo', 'principalEmail', default='<UNKNOWN>')}"

def alert_context(event):
    return gcp_alert_context(event) 