USER_SUSPENSION_ACTIONS = {
    "create",
    "update",
}


def rule(event):
    return (
        event.get("source_type") == "account_setting"
        and event.get("action", "") in USER_SUSPENSION_ACTIONS
        and event.get("source_label", "").lower() in {"account assumption", "assumption duration"}
    )


def generate_alert_title(event):
    return f"ALERT: Zendesk user [{event.udm('actor_user')}] modified support user assumption settings"
