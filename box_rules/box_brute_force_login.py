from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type") == "FAILED_LOGIN"


def title(event):
    return "User [{}] has exceeded the failed login threshold.".format(
        deep_get(event, "source", "name", default="<UNKNOWN_USER>")
    )
