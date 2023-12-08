from global_filter_azuresignin import filter_include_event
from panther_azuresignin_helpers import actor_user, azure_signin_alert_context, is_sign_in_event
from panther_base_helpers import deep_get

PASSTHROUGH_SEVERITIES = {"low", "medium", "high"}


def rule(event):
    if not is_sign_in_event(event):
        return False

    if not filter_include_event(event):
        return False
    global IDENTIFIED_RISK_LEVEL  # pylint: disable=global-variable-undefined
    IDENTIFIED_RISK_LEVEL = ""
    # Do not pass through risks marked as dismissed or remediated in AD
    if deep_get(event, "properties", "riskState", default="").lower() in [
        "dismissed",
        "remediated",
    ]:
        return False
    # check riskLevelAggregated
    for risk_type in ["riskLevelAggregated", "riskLevelDuringSignIn"]:
        if deep_get(event, "properties", risk_type, default="").lower() in PASSTHROUGH_SEVERITIES:
            IDENTIFIED_RISK_LEVEL = deep_get(event, "properties", risk_type).lower()
            return True
    return False


def title(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return f"AzureSignIn: RiskRanked Activity for Principal [{principal}]"


def dedup(event):
    principal = actor_user(event)
    source_ip = event.udm("source_ip")
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return principal + source_ip


def alert_context(event):
    a_c = azure_signin_alert_context(event)
    a_c["riskLevel"] = IDENTIFIED_RISK_LEVEL
    return a_c


def severity(_):
    if IDENTIFIED_RISK_LEVEL:
        return IDENTIFIED_RISK_LEVEL
    return "INFO"
