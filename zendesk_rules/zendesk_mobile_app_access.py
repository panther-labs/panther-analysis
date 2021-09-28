from panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION

MOBILE_APP_ACTIONS = {"create", "update"}


def rule(event):
    return (
        event.get("source_type") == "account_setting"
        and event.get("action", "") in MOBILE_APP_ACTIONS
        and event.get("source_label", "") == "Zendesk Support Mobile App Access"
    )


def title(event):
    action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
    return f"User [{event.udm('actor_user')}] {action} mobile app access"


def severity(event):
    if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
        return "INFO"
    return "MEDIUM"
