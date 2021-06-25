from panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION

REDACTION_ACTIONS = {
    "create",
    "destroy",
}

def rule(event):
    return (
        event.get("source_type") == "account_setting" and
        event.get("action", "") in REDACTION_ACTIONS and
        event.get("source_label", "") == "Credit Card Redaction"
    )


def title(event):
    action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
    return f"User [{event.udm('actor_user')}] {action} credit card redaction"


def severity(event):
    if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() != "disabled":
        return "INFO"
    return "HIGH"
