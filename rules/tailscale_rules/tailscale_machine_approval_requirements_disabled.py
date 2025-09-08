from panther_tailscale_helpers import is_tailscale_admin_console_event, tailscale_alert_context


def rule(event):

    action = event.deep_get("event", "action", default="<NO_ACTION_FOUND>")
    target_property = event.deep_get(
        "event", "target", "property", default="<NO_TARGET_PROPERTY_FOUND>"
    )
    return all(
        [
            action == "DISABLE",
            target_property == "MACHINE_APPROVAL_NEEDED",
            is_tailscale_admin_console_event(event),
        ]
    )


def title(event):
    user = event.deep_get("event", "actor", "loginName", default="<NO_USER_FOUND>")
    return (
        f"Tailscale user [{user}] disabled device approval requirements "
        f"for new devices accessing your organization’s network."
    )


def alert_context(event):
    return tailscale_alert_context(event)
