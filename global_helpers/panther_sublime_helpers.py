def sublime_alert_context(event) -> dict:
    context = {}
    context["key"] = event.get("key", "<KEY_NOT_FOUND>")
    context["events_types"] = event.deep_walk("events", "type", default=["<TYPES_NOT_FOUND>"])
    context["users_emails"] = event.deep_walk(
        "events", "created_by", "email_address", default=["<EMAILS_NOT_FOUND>"]
    )
    context["users_roles"] = event.deep_walk(
        "events", "created_by", "role", default=["<ROLES_NOT_FOUND>"]
    )
    context["request_ips"] = event.deep_walk(
        "events", "data", "request", "ip", default=["<IPS_NOT_FOUND>"]
    )
    context["request_paths"] = event.deep_walk(
        "events", "data", "request", "path", default=["<PATHS_NOT_FOUND>"]
    )
    return context
