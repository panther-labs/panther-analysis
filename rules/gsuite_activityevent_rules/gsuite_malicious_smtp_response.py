from panther_gsuite_helpers import gsuite_activityevent_alert_context

# SMTP response reasons that indicate security threats
MALICIOUS_SMTP_RESPONSES = {
    3: "Malware",
    13: "Blatant Spam",
    14: "Denial of Service",
    15: "Malicious or Spam Links",
    16: "Low IP Reputation",
    17: "Low Domain Reputation",
    18: "IP address listed in public real-time block list",
}


def rule(event):
    if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
        return False

    smtp_response_reason = event.deep_get(
        "parameters", "message_info", "connection_info", "smtp_response_reason", default=0
    )

    return smtp_response_reason in MALICIOUS_SMTP_RESPONSES


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    smtp_response_reason = event.deep_get(
        "parameters", "message_info", "connection_info", "smtp_response_reason", default=0
    )
    reason_description = MALICIOUS_SMTP_RESPONSES.get(
        smtp_response_reason, f"Unknown ({smtp_response_reason})"
    )

    sender = event.deep_get(
        "parameters", "message_info", "source", "address", default="<UNKNOWN_SENDER>"
    )

    return f"Gmail blocked email to [{user}] from [{sender}] due to: {reason_description}"


def alert_context(event):
    context = gsuite_activityevent_alert_context(event)

    # Add specific SMTP response information
    smtp_response_reason = event.deep_get(
        "parameters", "message_info", "connection_info", "smtp_response_reason", default=0
    )

    context.update(
        {
            "smtp_response_reason_code": smtp_response_reason,
            "smtp_response_reason": MALICIOUS_SMTP_RESPONSES.get(
                smtp_response_reason, f"Unknown ({smtp_response_reason})"
            ),
            "smtp_reply_code": event.deep_get(
                "parameters", "message_info", "connection_info", "smtp_reply_code", default=0
            ),
        }
    )

    return context
