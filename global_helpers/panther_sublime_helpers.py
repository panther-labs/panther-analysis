def sublime_alert_context(event) -> dict:
    context = {}
    context["events_type"] = event.get("type", "<TYPE_NOT_FOUND>")
    context["users_emails"] = event.deep_get(
        "created_by", "email_address", default="<EMAIL_NOT_FOUND>"
    )
    context["users_role"] = event.deep_get("created_by", "role", default="<ROLES_NOT_FOUND>")
    context["request_ip"] = event.deep_get("data", "request", "ip", default="<IP_NOT_FOUND>")
    context["request_path"] = event.deep_get("data", "request", "path", default="<PATH_NOT_FOUND>")
    return context
