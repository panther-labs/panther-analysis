from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype", "") == "group.privilege.grant"


def title(event):
    # pylint: disable=W0613
    return (
        "Okta Admin Privileges Assigned to Group "
        f"[{event.get('target', [{}])[0].get('alternateId', '<id-not-found>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
