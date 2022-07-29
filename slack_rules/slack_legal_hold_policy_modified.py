from panther_base_helpers import deep_get, slack_alert_context

LEGAL_HOLD_POLICY_ACTIONS = {
    "legal_hold_policy_entities_deleted": "Slack Legal Hold Policy Entities Deleted",
    "legal_hold_policy_exclusion_added": "Slack - Exclusions Added to Legal Hold Policy",
    "legal_hold_policy_released": "Slack Legal Hold Released",
    "legal_hold_policy_updated": "Slack Legal Hold Updated",
}


def rule(event):
    return event.get("action") in LEGAL_HOLD_POLICY_ACTIONS


def title(event):
    # Only the `legal_hold_policy_updated` event includes relevant data to deduplicate
    if event.get("action") == "legal_hold_policy_updated":
        return f"Slack Legal Hold Updated " \
               f"[{deep_get(event, 'details', 'old_legal_hold_policy', 'name')}]"
    if event.get("action") in LEGAL_HOLD_POLICY_ACTIONS:
        return LEGAL_HOLD_POLICY_ACTIONS.get(event.get("action"))
    return "Slack Legal Hold Policy Modified"


def alert_context(event):
    return slack_alert_context(event)
