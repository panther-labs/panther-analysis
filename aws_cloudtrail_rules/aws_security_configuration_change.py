from panther_base_helpers import deep_get

SECURITY_CONFIG_ACTIONS = {
    "DeleteAccountPublicAccessBlock",
    "DeleteDeliveryChannel",
    "DeleteDetector",
    "DeleteFlowLogs",
    "DeleteRule",
    "DeleteTrail",
    "DisableEbsEncryptionByDefault",
    "DisableRule",
    "StopConfigurationRecorder",
    "StopLogging",
}


def rule(event):
    if event.get("eventName") == "UpdateDetector":
        return not deep_get(event, "requestParameters", "enable", default=True)

    return event.get("eventName") in SECURITY_CONFIG_ACTIONS


def title(event):
    user = deep_get(event, "userIdentity", "userName") or deep_get(
        event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
    )

    return f"Sensitive AWS API call {event.get('eventName')} made by {user}"
