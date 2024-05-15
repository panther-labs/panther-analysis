from panther_default import lookup_aws_account_name
from panther_oss_helpers import geoinfo_from_ip_formatted


def rule(event):
    return (
        event.udm("event_name") == "ConsoleLogin"
        and event.udm("user_type") == "Root"
        and event.udm("login_status") == "Success"
    )


def title(event):
    ip_address = event.udm("source_ip_address")
    return (
        f"AWS root login detected from [{ip_address}] "
        f"({geoinfo_from_ip_formatted(ip_address)}) "
        f"in account "
        f"[{lookup_aws_account_name(event.udm('recipient_account_id'))}]"
    )


def dedup(event):
    # Each Root login should generate a unique alert
    return "-".join(
        [
            event.udm("recipient_account_id", default="<RECIPIENT_ACCOUNT_ID_NOT_FOUND>"),
            event.udm("event_name", default="<EVENT_NAME_NOT_FOUND>"),
            event.udm("event_time", default="<EVENT_TIME_NOT_FOUND>"),
        ]
    )


def alert_context(event):
    return {
        "sourceIPAddress": event.udm("source_ip_address"),
        "userIdentityAccountId": event.udm("user_account_id"),
        "userIdentityArn": event.udm("user_arn"),
        "eventTime": event.udm("event_time"),
        "mfaUsed": event.udm("mfa_used"),
    }
