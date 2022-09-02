from panther_base_helpers import slack_alert_context

IDP_CHANGE_ACTIONS = {
    "idp_configuration_added": "Slack IDP Configuration Added",
    "idp_configuration_deleted": "Slack IDP Configuration Deleted",
    "idp_prod_configuration_updated": "Slack IDP Configuration Updated",
}


def rule(event):
    return event.get("action") in IDP_CHANGE_ACTIONS


def title(event):
    if event.get("action") in IDP_CHANGE_ACTIONS:
        return IDP_CHANGE_ACTIONS.get(event.get("action"))
    return "Slack IDP Configuration Changed"


def alert_context(event):
    return slack_alert_context(event)
