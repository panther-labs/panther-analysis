from panther_okta_helpers import okta_alert_context

# Event types indicating suspicious AD agent activity
SUSPICIOUS_AD_AGENT_EVENTS = [
    "system.agent.ad.config_change_detected",  # AD agent configuration modified
    "system.agent.ad.agent_instance_added",  # New AD agent instance registered
    "system.agent.ad.bad_credentials",  # Failed AD agent authentication
]


def rule(event):
    event_type = event.get("eventType", "")
    outcome = event.deep_get("outcome", "result", default="")

    # Check for suspicious AD agent-related events on failures
    if event_type in SUSPICIOUS_AD_AGENT_EVENTS and outcome in ["FAILURE", "ERROR"]:
        return True

    # Detect API token usage from AD service accounts in unusual circumstances
    if event_type == "system.api_token.create":
        actor_alt_id = event.deep_get("actor", "alternateId", default="")
        # Check if actor is a service account (common patterns for AD agent accounts)
        if any(keyword in actor_alt_id.lower() for keyword in ["svc", "service", "agent", "sync"]):
            return True

    return False


def title(event):
    event_type = event.get("eventType", "<UNKNOWN_EVENT>")
    actor = event.deep_get("actor", "displayName", default="<UNKNOWN_ACTOR>")
    target = event.get("target", [{}])

    if "config_change" in event_type:
        return f"Failed Okta AD Agent Configuration Change by {actor}"
    if "agent_instance_added" in event_type:
        return f"Failed Okta AD Agent Instance Registration by {actor}"
    if "bad_credentials" in event_type:
        return f"Failed Okta AD Agent Authentication: {actor}"
    if event_type == "system.api_token.create":
        token_name = (
            target[0].get("displayName", "<UNKNOWN_TOKEN>") if target else "<UNKNOWN_TOKEN>"
        )
        return f"API Token Created by Service Account {actor}: {token_name}"

    return f"Suspicious Okta AD Agent Activity: {event_type}"


def severity(event):
    event_type = event.get("eventType", "")
    outcome = event.deep_get("outcome", "result", default="")

    # New agent registration is high severity (potential rogue agent)
    if "agent_instance_added" in event_type:
        return "HIGH"

    # Config changes are medium-high severity
    if "config_change" in event_type:
        return "MEDIUM"

    # Failed authentications could indicate brute force or token issues
    if outcome in ["FAILURE", "ERROR"]:
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    context = okta_alert_context(event)

    # Add AD agent-specific context
    context["event_type"] = event.get("eventType", "<UNKNOWN_EVENT_TYPE>")
    context["display_message"] = event.get("displayMessage", "<UNKNOWN_MESSAGE>")

    # Add transaction details for tracking
    transaction = event.get("transaction", {})
    if transaction:
        context["transaction_id"] = transaction.get("id", "<UNKNOWN_TRANSACTION_ID>")
        context["transaction_type"] = transaction.get("type", "<UNKNOWN_TRANSACTION_TYPE>")

    return context
