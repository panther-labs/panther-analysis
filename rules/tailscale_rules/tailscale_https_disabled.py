from global_filter_tailscale import filter_include_event
from panther_base_helpers import deep_get
from panther_tailscale_helpers import (
    is_tailscale_admin_console_event,
    tailscale_alert_context,
)


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "action", default="<NO_ACTION_FOUND>")
    target_property = deep_get(event, "target", "property", default="<NO_TARGET_PROPERTY_FOUND>")
    return all(
        [
            action == "DISABLE",
            target_property == "HTTPS",
            is_tailscale_admin_console_event(event),
        ]
    )


def title(event):
    user = deep_get(event, "actor", "loginName", default="<NO_USER_FOUND>")
    target_id = deep_get(event, "target", "id", default="<NO_TARGET_ID_FOUND>")
    return (
        f"Tailscale user [{user}] disabled HTTPS for "
        f"[{target_id}] in your organization’s tenant."
    )


def alert_context(event):
    return tailscale_alert_context(event)
