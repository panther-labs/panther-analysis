import panther_event_type_helpers as event_type


def rule(event):
    # filter events on unified data model field
    return event.udm("event_type") == event_type.ADMIN_ROLE_ASSIGNED


def title(event):
    # use unified data model field in title
    recipient = event.udm("user") or event.get("team") or "USER_OR_TEAM_NOT_FOUND"
    return (
        f"{event.get('p_log_type')}: [{event.udm('actor_user')}] assigned admin privileges "
        f"[{event.udm('assigned_admin_role')}] to [{recipient}]"
    )


def alert_context(event):
    return {
        "ips": event.get("p_any_ip_addresses", []),
        "actor": event.udm("actor_user"),
        "user": event.udm("user"),
    }
