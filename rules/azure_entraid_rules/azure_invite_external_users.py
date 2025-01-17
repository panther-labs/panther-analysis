from panther_azure_helpers import azure_rule_context
from panther_base_helpers import deep_walk


def rule(event):
    result = event.deep_get("properties", "result", default="")
    if result != "success":
        return False

    if event.get("operationName") != "Invite external user":
        return False

    user_who_sent_invite = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    user_who_received_invite = deep_walk(
        event, "properties", "additionalDetails", "value", return_val="last", default=""
    )
    domain = user_who_sent_invite.split("@")[-1]

    different_domain = not user_who_received_invite.endswith(domain)

    return different_domain


def title(event):
    user_who_sent_invite = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    user_who_received_invite = deep_walk(
        event, "properties", "additionalDetails", "value", return_val="last", default=""
    )

    return (
        f"{user_who_sent_invite} invited {user_who_received_invite} to join as an EntraID member."
    )


def alert_context(event):
    return azure_rule_context(event)
