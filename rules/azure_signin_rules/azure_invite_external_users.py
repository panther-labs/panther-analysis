from panther_msft_helpers import azure_rule_context, azure_success


def rule(event):
    if not azure_success(event) or event.get("operationName") != "Invite external user":
        return False

    user_who_sent_invite = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    user_who_received_invite = event.deep_walk(
        "properties", "additionalDetails", "value", return_val="last", default=""
    )
    domain = user_who_sent_invite.split("@")[-1]

    different_domain = not user_who_received_invite.endswith(domain)

    return different_domain


def title(event):
    user_who_sent_invite = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    user_who_received_invite = event.deep_walk(
        "properties", "additionalDetails", "value", return_val="last", default=""
    )

    return (
        f"{user_who_sent_invite} invited {user_who_received_invite} to join as an EntraID member."
    )


def alert_context(event):
    return azure_rule_context(event)
