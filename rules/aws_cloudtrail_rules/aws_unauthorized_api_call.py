from ipaddress import ip_address

from panther_aws_helpers import aws_rule_context
from panther_misp_helpers import get_misp_warning_lists

# Do not alert on these access denied errors for these events.
# Events could be exceptions because they are particularly noisy and provide little to no value,
# or because they are expected as part of the normal operating procedure for certain tools.
EVENT_EXCEPTIONS = {
    "DescribeEventAggregates",  # Noisy, doesn't really provide any actionable info
    "ListResourceTags",  # The audit role hits this when scanning locked down resources
}


def rule(event):
    source_ip = event.get("sourceIPAddress")

    try:
        ip_address(source_ip)
    except ValueError:
        return False

    # Filter out known Amazon IP ranges
    misp_data = get_misp_warning_lists(event)
    if misp_data and misp_data.has_warning_list_id(source_ip, "amazon-aws"):
        return False

    return (
        event.get("errorCode") == "AccessDenied" and event.get("eventName") not in EVENT_EXCEPTIONS
    )


def dedup(event):
    return event.udm("actor_user")


def title(event):
    return f"Access denied to {event.deep_get('userIdentity', 'type')} [{dedup(event)}]"


def alert_context(event):
    return aws_rule_context(event)
