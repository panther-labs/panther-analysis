from global_filter_tailscale import filter_include_event
from panther_tailscale_helpers import tailscale_alert_context, is_tailscale_admin_console_event
from panther_base_helpers import deep_get


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "action", default="<NO_ACTION_FOUND>")
    target_property = deep_get(event, "target", "property",  default="<NO_TARGET_PROPERTY_FOUND>")
    return all(
        [
            action == "DISABLE",
            target_property == "MACHINE_APPROVAL_NEEDED",
            is_tailscale_admin_console_event(event),
        ]
    )


def title(event):
    user = deep_get(event, "actor", "loginName",  default="<NO_USER_FOUND>")
    return (
        f"Tailscale user [{user}] disabled device approval requirements "
        f"for new devices before accessing your organization’s network."
    )


def alert_context(event):
    return tailscale_alert_context(event)
