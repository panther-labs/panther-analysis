from panther_base_helpers import aws_rule_context

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
        and not event.deep_get("userIdentity", "arn", default="").endswith(
            f"/{event.deep_get('requestParameters', 'userName', default='')}"
        )
    )


def title(event):
    return (
        f"[{event.deep_get('userIdentity', 'arn')}] "
        f"changed the password for "
        f"[{event.deep_get('requestParameters','userName')}]"
    )


def alert_context(event):
    context = aws_rule_context(event)
    context["ip_and_username"] = event.get(
        "sourceIPAddress", "<MISSING_SOURCE_IP>"
    ) + event.deep_get("requestParameters", "userName", default="<MISSING_USER_NAME>")
    return context
