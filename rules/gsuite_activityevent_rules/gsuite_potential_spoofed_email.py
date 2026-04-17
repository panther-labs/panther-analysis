from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):

    if event.deep_get("id", "applicationName", default="<UNKNOWN_APPLICATION>") != "gmail":
        return False

    dmarc_passed = event.deep_get(
        "parameters",
        "message_info",
        "connection_info",
        "dmarc_pass",
        default="<UNKNOWN_DMARC_PASS>",
    )
    spf_passed = event.deep_get(
        "parameters", "message_info", "connection_info", "spf_pass", default="<UNKNOWN_SPF_PASS>"
    )
    dkim_passed = event.deep_get(
        "parameters",
        "message_info",
        "connection_info",
        "dkim_pass",
        default="<UNKNOWN_DKIM_PASS>",
    )

    event_success = event.deep_get("parameters", "event_info", "success", default=False)

    if event_success is True:  # Message was delivered despite failures
        if dmarc_passed is False:
            return True
        if spf_passed is False and dkim_passed is False:
            return True
    return False


def title(event):
    user = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    return f"[{user}] received a potentially spoofed email"


def alert_context(event):
    context = gsuite_activityevent_alert_context(event)
    return context
