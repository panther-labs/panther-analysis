from panther_asana_helpers import asana_alert_context


def rule(event):
    new = event.deep_get("details", "new_value", default="")
    old = event.deep_get("details", "old_value", default="")
    return all(
        [
            event.get("event_type") == "user_workspace_admin_role_changed",
            "admin" in new,
            "admin" not in old,
        ]
    )


def title(event):
    a_c = asana_alert_context(event)
    w_s = event.deep_get("details", "group", "name", default="<WS_NAME_NOT_FOUND>")
    return (
        f"Asana user [{a_c.get('resource_name')}] was made an admin "
        f"in workspace [{w_s}] by [{a_c.get('actor')}]."
    )


def alert_context(event):
    return asana_alert_context(event)
