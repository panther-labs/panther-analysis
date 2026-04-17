from panther_azuresignin_helpers import actor_user, azure_signin_alert_context, is_sign_in_event

PASSTHROUGH_SEVERITIES = {"low", "medium", "high"}


def rule(event):
    if not is_sign_in_event(event):
        return False

    global IDENTIFIED_RISK_LEVEL  # pylint: disable=global-variable-undefined
    IDENTIFIED_RISK_LEVEL = ""
    # Do not pass through risks marked as dismissed or remediated in AD
    if event.deep_get("properties", "riskState", default="").lower() in [
        "dismissed",
        "remediated",
    ]:
        return False
    # check riskLevelAggregated
    for risk_type in ["riskLevelAggregated", "riskLevelDuringSignIn"]:
        if event.deep_get("properties", risk_type, default="").lower() in PASSTHROUGH_SEVERITIES:
            IDENTIFIED_RISK_LEVEL = event.deep_get("properties", risk_type).lower()
            return True
    return False


def title(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return f"AzureSignIn: RiskRanked Activity for Principal [{principal}]"


def alert_context(event):
    a_c = azure_signin_alert_context(event)
    a_c["riskLevel"] = IDENTIFIED_RISK_LEVEL
    return a_c


def severity(_):
    if IDENTIFIED_RISK_LEVEL:
        return IDENTIFIED_RISK_LEVEL
    return "INFO"
