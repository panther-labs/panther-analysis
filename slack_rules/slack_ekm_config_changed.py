from panther_base_helpers import slack_alert_context


def rule(event):
    # Only alert on the `ekm_logging_config_set` action
    return event.get("action") == "ekm_logging_config_set"


def alert_context(event):
    # TODO: Add details to the context
    return slack_alert_context(event)
