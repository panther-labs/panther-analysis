from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("event_type") == "team_privacy_settings_changed"
        and deep_get(event, "details", "new_value") == "public"
    )


def title(event):
    team = deep_get(event, "resource", "name", default="<TEAM_NOT_FOUND>")
    actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    return f"Asana team [{team}] has been made public to the org by [{actor}]."


# def dedup(event):
#  (Optional) Return a string which will be used to deduplicate similar alerts.
# return ''

# def alert_context(event):
#  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination
# return {'key':'value'}
