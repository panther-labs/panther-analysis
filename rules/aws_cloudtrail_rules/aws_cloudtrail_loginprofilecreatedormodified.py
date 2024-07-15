from panther_base_helpers import aws_rule_context, deep_get

PROFILE_EVENTS = {
    "UpdateLoginProfile",
    "CreateLoginProfile",
}


def rule(event):
    # Only look for successes
    if event.get("errorCode") or event.get("errorMessage"):
        return False

    # Check when someone other than the user themselves creates or modifies a login profile
    return (
        event.get("eventSource", "") == "iam.amazonaws.com"
        and event.get("eventName", "") in PROFILE_EVENTS
        and not deep_get(event, "userIdentity", "arn", default="").endswith(
            f"/{deep_get(event, 'requestParameters', 'userName', default='')}"
        )
    )


def title(event):
    return (
        f"[{deep_get(event, 'userIdentity', 'arn')}] "
        f"changed the password for "
        f"[{deep_get(event, 'requestParameters','userName')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
