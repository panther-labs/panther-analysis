from ipaddress import ip_address

from panther_base_helpers import aws_rule_context

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
        ip_address(event.udm("source_ip_address"))
    except ValueError:
        return False
    return (
        event.udm("error_code") == "AccessDenied"
        and event.udm("event_name") not in EVENT_EXCEPTIONS
    )


def dedup(event):
    return event.udm("user_principal_id", default="<UNKNOWN_PRINCIPAL>")


def title(event):
    return f"Access denied to {event.udm('user_type')} [{dedup(event)}]"


def alert_context(event):
    return aws_rule_context(event)
