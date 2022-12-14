from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype") == "user.account.report_suspicious_activity_by_enduser"


def title(event):
    reported_event_type = (
        event.get("debugcontext", {})
        .get("debugData", {})
        .get("suspiciousActivityEventType", "<event-type-not-found>")
    )
    return (
        f"Okta [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"reported suspicious account activity [{reported_event_type}] "
    )


def alert_context(event):
    return okta_alert_context(event)
