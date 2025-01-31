import json

from panther_base_helpers import deep_walk
from panther_msft_helpers import azure_rule_context


def get_mfa(policy):
    parse_one = json.loads(policy)

    mfa_get = deep_walk(parse_one, "grantControls", "builtInControls", default=[])
    mfa_standardized = [n.lower() for n in mfa_get]
    return mfa_standardized


def rule(event):
    if event.get("operationName", default="") != "Update conditional access policy":
        return False

    old_value = event.deep_walk(
        "properties",
        "targetResources",
        "modifiedProperties",
        "oldValue",
        return_val="first",
        default="",
    )
    new_value = event.deep_walk(
        "properties",
        "targetResources",
        "modifiedProperties",
        "newValue",
        return_val="first",
        default="",
    )

    old_value_parsed = get_mfa(old_value)
    new_value_parsed = get_mfa(new_value)

    return "mfa" in old_value_parsed and "mfa" not in new_value_parsed


def title(event):
    actor_name = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    policy = event.deep_walk("properties", "targetResources", "displayName", default="")

    return f"MFA disabled by {actor_name} on the policy {policy}"


def alert_context(event):
    return azure_rule_context(event)
