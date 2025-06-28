EVENT_NAMES = [
    "CreateSAMLProvider",
    "DeleteSAMLProvider",
    "UpdateSAMLProvider",
    "CreateOpenIDConnectProvider",
    "DeleteOpenIDConnectProvider",
]

EVENT_SOURCE = "iam.amazonaws.com"

ALLOWED_USERS = ["pulumi", "AtlantisRole"]


def rule(event):
    does_event_name_match: bool = event.get("eventName") in EVENT_NAMES
    does_event_source_match: bool = event.get("eventSource") == EVENT_SOURCE
    session_user_name: str = event.deep_get(
        "userIdentity", "sessionContext", "sessionIssuer", "userName"
    )
    does_session_user_match: bool = session_user_name in ALLOWED_USERS

    if does_event_name_match and does_event_source_match and not does_session_user_match:
        return True
    return False


def title(event):
    return (
        f"User [{event.deep_get('userIdentity', 'arn')}]"
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )
