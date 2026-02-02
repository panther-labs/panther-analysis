import json

from panther_azuresignin_helpers import (
    azure_signin_alert_context,
    azure_signin_success,
    is_sign_in_event,
)
from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "Azure.SignIn.MultipleProtectionAlerts"

# Minimum number of risk events to trigger alert
MIN_RISK_EVENTS = 3

# Risk states that indicate protection alerts
RISK_STATES = {
    "atrisk",
    "confirmedcompromised",
}

# Risk levels that should be tracked
RISK_LEVELS = {
    "high",
    "medium",
}


def rule(event):
    if not is_sign_in_event(event) or not azure_signin_success(event):
        return False

    # Only track events with actual risk
    risk_state = event.deep_get("properties", "riskState", default="")
    if not risk_state or risk_state.lower() not in RISK_STATES:
        return False
    risk_state = risk_state.lower()

    # Check risk levels
    risk_level_during = event.deep_get("properties", "riskLevelDuringSignIn", default="").lower()
    risk_level_agg = event.deep_get("properties", "riskLevelAggregated", default="").lower()

    has_risk = risk_level_during in RISK_LEVELS or risk_level_agg in RISK_LEVELS

    if not has_risk:
        return False

    # Get user principal name for tracking
    user_principal_name = event.deep_get("properties", "userPrincipalName", default="")
    if not user_principal_name:
        return False

    time_stamp = event.get("time", "")
    if not time_stamp:
        return False

    cache_key = f"{user_principal_name}-{RULE_ID}"
    event_set = add_to_string_set(cache_key, [time_stamp])

    # Handle unit test mocks
    if isinstance(event_set, str):
        event_set = json.loads(event_set) if event_set else []

    # Alert if user has 3+ risk events within the cache window (15 minutes)
    return len(event_set) >= MIN_RISK_EVENTS


def title(event):
    user_principal_name = event.deep_get(
        "properties", "userPrincipalName", default="<UNKNOWN_USER>"
    )
    return (
        f"Multiple Entra ID Protection Alerts: User [{user_principal_name}] "
        f"has multiple risk events "
    )


def alert_context(event):
    context = azure_signin_alert_context(event)

    # Add risk-specific context
    context["risk_state"] = event.deep_get("properties", "riskState", default="<NO_RISK_STATE>")
    context["risk_level_during_signin"] = event.deep_get(
        "properties", "riskLevelDuringSignIn", default="<NO_RISK_LEVEL>"
    )
    context["risk_level_aggregated"] = event.deep_get(
        "properties", "riskLevelAggregated", default="<NO_RISK_LEVEL>"
    )
    context["risk_detail"] = event.deep_get("properties", "riskDetail", default="<NO_RISK_DETAIL>")
    context["risk_event_types"] = event.deep_get(
        "properties", "riskEventTypes", default="<NO_RISK_TYPES>"
    )

    # Add authentication details
    context["authentication_protocol"] = event.deep_get(
        "properties", "authenticationProtocol", default="<NO_PROTOCOL>"
    )
    context["client_app_used"] = event.deep_get(
        "properties", "clientAppUsed", default="<NO_CLIENT_APP>"
    )
    context["device_detail_browser"] = event.deep_get(
        "properties", "deviceDetail", "browser", default="<NO_BROWSER>"
    )
    context["device_detail_os"] = event.deep_get(
        "properties", "deviceDetail", "operatingSystem", default="<NO_OS>"
    )
    context["is_interactive"] = event.deep_get("properties", "isInteractive", default=None)
    context["user_agent"] = event.deep_get("properties", "userAgent", default="<NO_USER_AGENT>")

    # Add location details
    context["location_city"] = event.deep_get("properties", "location", "city", default="<NO_CITY>")
    context["location_country"] = event.deep_get(
        "properties", "location", "countryOrRegion", default="<NO_COUNTRY>"
    )

    return context
