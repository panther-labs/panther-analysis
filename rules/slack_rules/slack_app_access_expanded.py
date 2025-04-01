from panther_slack_helpers import slack_alert_context

ACCESS_EXPANDED_ACTIONS = [
    "app_scopes_expanded",
    "app_resources_added",
    "app_resources_granted",
    "bot_token_upgraded",
]


def rule(event):
    if event.get("action") not in ACCESS_EXPANDED_ACTIONS:
        return False

    # Check to confirm that app scopes actually expanded or not
    if event.get("action") == "app_scopes_expanded":
        changes = get_scope_changes(event)
        if not changes["added"]:
            return False
    return True


def title(event):
    return (
        f"Slack App [{event.deep_get('entity', 'app', 'name')}] "
        f"Access Expanded by [{event.deep_get('actor', 'user', 'name')}]"
    )


def alert_context(event):
    context = slack_alert_context(event)

    # Diff previous and new scopes
    new_scopes = event.deep_get("details", "new_scopes", default=[])
    prv_scopes = event.deep_get("details", "previous_scopes", default=[])

    changes = get_scope_changes(event)
    context["scopes_added"] = changes["added"]
    context["scopes_removed"] = changes["removed"]

    return context


def get_scope_changes(event) -> dict[str, list[str]]:
    changes = {}

    new_scopes = event.deep_get("details", "new_scopes", default=[])
    prv_scopes = event.deep_get("details", "previous_scopes", default=[])

    changes["added"] = [x for x in new_scopes if x not in prv_scopes]
    changes["removed"] = [x for x in prv_scopes if x not in new_scopes]

    return changes


def severity(event):
    # Used to escalate to High/Critical if the app is granted admin privileges
    # May want to escalate to "Critical" depending on security posture
    if "admin" in event.deep_get("entity", "app", "scopes", default=[]):
        return "High"

    # Fallback method in case the admin scope is not directly mentioned in entity for whatever
    if "admin" in event.deep_get("details", "new_scope", default=[]):
        return "High"

    if "admin" in event.deep_get("details", "bot_scopes", default=[]):
        return "High"

    return "Medium"
