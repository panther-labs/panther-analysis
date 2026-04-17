from panther_slack_helpers import slack_alert_context

ELEVATED_ANOMALIES = {"excessive_malware_uploads", "session_fingerprint", "unexpected_admin_action"}


def rule(event):
    return event.get("action") == "anomaly"


def severity(event):
    # Return "MEDIUM" for some more serious anomalies
    reasons = event.deep_get("details", "reason", default=[])
    if set(reasons) & ELEVATED_ANOMALIES:
        return "MEDIUM"
    return "DEFAULT"


def title(event):
    anomalies = {
        "asn": "An ASN was on a list of suspicious ASNs",
        "excessive_downloads": "A user downloaded an excessive amount of files",
        "excessive_file_shares": "A user shared an excessive amount of files",
        "excessive_malware_uploads": "A user uploaded an excessive amount of malware files",
        "ip_address": "An anomaly was detected in the IP address used for the user token",
        "search_volume": "An unusual volume of search activity was detected",
        "session_fingerprint": "The session cookie has an unusual timestamp or client fingerprint",
        "spoofed_user_agent": "Characteristics of the client do not match the user agent",
        "tor": "A Tor exit node was used",
        "unexpected_admin_action": "An unexpected admin action was performed",
        "unexpected_api_call_volume": "An unexpected volume of API calls was detected",
        "unexpected_client": "An anomalous Slack client was detected",
        "unexpected_credential_testing": "Unexpected credential testing activity was detected",
        "unexpected_message_deletion": "Unexpected message deletion activity was detected",
        "unexpected_scraping": "Unexpected scraping activity was detected",
        "unexpected_user_agent": "An unexpected user agent was detected",
        "user_agent": "An anomaly was detected in the user agent used for the user token",
    }

    reasons = event.deep_get("details", "reason", default=[])
    reasons_str = reasons[0] if reasons else ""
    anomaly_description = anomalies.get(reasons_str)

    actor = event.deep_get("actor", "user", "email", default="")
    actor_str = f" for {actor}" if actor else ""

    if anomaly_description:
        return f"Slack Anomaly Detected{actor_str}: {anomaly_description}"
    # if the anomaly is not in our list (for future use)
    return f"Slack Anomaly Detected{actor_str}"


def alert_context(event):
    context = slack_alert_context(event)
    context |= {"details": event.get("details", {}), "context": event.get("context", {})}
    return context
