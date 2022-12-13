from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype", "") == "group.privilege.grant"


def title(event):
    # pylint: disable=W0613
    return "Okta Admin Privileges Assigned to Group"


def alert_context(event):
    return okta_alert_context(event)
