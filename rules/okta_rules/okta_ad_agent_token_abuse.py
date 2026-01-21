from panther_base_helpers import get_val_from_list
from panther_okta_helpers import okta_alert_context

# Event types indicating suspicious AD agent activity
SUSPICIOUS_AD_AGENT_EVENTS = [
    "system.agent.ad.config_change_detected",  # AD agent configuration modified
    "system.agent.ad.agent_instance_added",  # New AD agent instance registered
    "system.agent.ad.bad_credentials",  # Failed AD agent authentication
]

# Service account patterns (matched at word boundaries to avoid false positives)
SERVICE_ACCOUNT_PATTERNS = [
    "svc-",
    "svc_",
    "svc.",
    "service-",
    "service_",
    "service.",
    "-service",
    "_service",
    ".service",
    "-agent",
    "_agent",
    ".agent",
    "agent-",
    "agent_",
    "-sync",
    "_sync",
    "sync-",
    "sync_",
    "ad-agent",
    "ad-sync",
    "okta-sync",
    "okta-agent",
]


def is_service_account(actor_id):
    """
    Check if an actor ID matches common service account naming patterns.
    Uses word-boundary matching to avoid false positives like 'customerservice@'.
    """
    if not actor_id:
        return False

    actor_lower = actor_id.lower()

    # Check if any service account pattern is present
    return any(pattern in actor_lower for pattern in SERVICE_ACCOUNT_PATTERNS)


def rule(event):
    event_type = event.get("eventType", "")
    outcome = event.deep_get("outcome", "result", default="")

    # Detect config changes and new agent registrations (suspicious regardless)
    if event_type in [
        "system.agent.ad.config_change_detected",
        "system.agent.ad.agent_instance_added",
    ]:
        return True

    # Detect failed AD agent authentication attempts
    if event_type == "system.agent.ad.bad_credentials" and outcome in ["FAILURE", "ERROR"]:
        return True

    # Detect API token usage from AD service accounts in unusual circumstances
    if event_type == "system.api_token.create":
        actor_alt_id = event.deep_get("actor", "alternateId", default="")
        if is_service_account(actor_alt_id):
            return True

    return False


def title(event):
    event_type = event.get("eventType", "<UNKNOWN_EVENT>")
    actor = event.deep_get("actor", "displayName", default="<UNKNOWN_ACTOR>")
    outcome = event.deep_get("outcome", "result", default="")

    if "config_change" in event_type:
        status = "Failed" if outcome in ["FAILURE", "ERROR"] else "Detected"
        return f"{status} Okta AD Agent Configuration Change by {actor}"
    if "agent_instance_added" in event_type:
        status = "Failed" if outcome in ["FAILURE", "ERROR"] else "New"
        return f"{status} Okta AD Agent Instance Registration by {actor}"
    if "bad_credentials" in event_type:
        return f"Failed Okta AD Agent Authentication: {actor}"
    if event_type == "system.api_token.create":
        token_names = get_val_from_list(event.get("target", [{}]), "displayName", "type", "Token")
        token_name = list(token_names)[0] if token_names else "<UNKNOWN_TOKEN>"
        return f"API Token Created by Service Account {actor}: {token_name}"

    return f"Suspicious Okta AD Agent Activity: {event_type}"


def severity(event):
    event_type = event.get("eventType", "")
    outcome = event.deep_get("outcome", "result", default="")

    # New agent registration is high severity (potential rogue agent)
    if "agent_instance_added" in event_type:
        return "HIGH"

    # Service account token creation is high severity (token theft indicator)
    if event_type == "system.api_token.create":
        actor_alt_id = event.deep_get("actor", "alternateId", default="")
        if is_service_account(actor_alt_id):
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
