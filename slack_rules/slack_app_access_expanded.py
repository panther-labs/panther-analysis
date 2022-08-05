from panther_base_helpers import deep_get, slack_alert_context

ACCESS_EXPANDED_ACTIONS = [
    "app_scopes_expanded",
    "app_resources_added",
    "app_resources_granted",
    "bot_token_upgraded",
]


def rule(event):
    return event.get("action") in ACCESS_EXPANDED_ACTIONS


def title(event):
    return f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] " \
           f"Access Expanded by [{deep_get(event, 'actor', 'user', 'name')}]"


def alert_context(event):
    context = slack_alert_context(event)

    # Diff previous and new scopes
    new_scopes = deep_get(event, "details", "new_scopes", default=[])
    prv_scopes = deep_get(event, "details", "previous_scopes", default=[])

    context["scopes_added"] = [x for x in new_scopes if x not in prv_scopes]
    context["scoped_removed"] = [x for x in prv_scopes if x not in new_scopes]

    return context


def severity(event):
    # Used to escalate to High/Critical if the app is granted admin privileges
    # May want to escalate to "Critical" depending on security posture
    if "admin" in deep_get(event, "entity", "app", "scopes", default=[]):
        return "High"

    # Fallback method in case the admin scope is not directly mentioned in entity for whatever
    if "admin" in deep_get(event, "details", "new_scope", default=[]):
        return "High"

    if "admin" in deep_get(event, "details", "bot_scopes", default=[]):
        return "High"

    return "Medium"
