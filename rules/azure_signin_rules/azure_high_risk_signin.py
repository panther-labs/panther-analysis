from panther_azuresignin_helpers import actor_user, azure_signin_alert_context, is_sign_in_event


def rule(event):
    if not is_sign_in_event(event):
        return False

    risk_state = event.deep_get("properties", "riskState", default="").lower()
    if risk_state in ["dismissed", "remediated"]:
        return False

    risk_level_during_signin = event.deep_get(
        "properties", "riskLevelDuringSignIn", default=""
    ).lower()
    risk_level_aggregated = event.deep_get("properties", "riskLevelAggregated", default="").lower()

    return risk_level_during_signin == "high" or risk_level_aggregated == "high"


def title(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"

    ip_address = event.deep_get("properties", "ipAddress", default="<UNKNOWN_IP>")

    return f"High-Risk Sign-In Detected: [{principal}] from [{ip_address}]"


def alert_context(event):
    context = azure_signin_alert_context(event)
    return context
