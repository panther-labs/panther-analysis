from ipaddress import ip_address

from panther_base_helpers import aws_rule_context, deep_get

# Do not alert on these access denied errors for these events.
# Events could be exceptions because they are particularly noisy and provide little to no value,
# or because they are expected as part of the normal operating procedure for certain tools.
EVENT_EXCEPTIONS = {
    "DescribeEventAggregates",  # Noisy, doesn't really provide any actionable info
    "ListResourceTags",  # The audit role hits this when scanning locked down resources
}


def rule(event):
    # Validate the request came from outside of AWS
    try:
        ip_address(event.get("sourceIPAddress"))
    except ValueError:
        return False
    return (
        event.get("errorCode") == "AccessDenied" and event.get("eventName") not in EVENT_EXCEPTIONS
    )


def dedup(event):
    return deep_get(event, "userIdentity", "principalId", default="<UNKNOWN_PRINCIPAL>")


def title(event):
    return f"Access denied to {deep_get(event, 'userIdentity', 'type')} [{dedup(event)}]"


def alert_context(event):
    return aws_rule_context(event)
