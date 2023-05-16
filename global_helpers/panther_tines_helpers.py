def tines_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.get("user_email", "<NO_USEREMAIL>")
    a_c["action"] = event.get("operation_name", "<NO_OPERATION>")
    a_c["tenant_id"] = event.get("tenant_id", "<NO_TENANTID>")
    return a_c
