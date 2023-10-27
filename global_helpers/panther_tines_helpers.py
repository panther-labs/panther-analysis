def tines_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.get("user_email", "<NO_USEREMAIL>")
    a_c["action"] = event.get("operation_name", "<NO_OPERATION>")
    a_c["tenant_id"] = event.get("tenant_id", "<NO_TENANTID>")
    a_c["user_email"] = event.get("user_email", "<NO_USEREMAIL>")
    a_c["user_id"] = event.get("user_id", "<NO_USERID>")
    a_c["operation_name"] = event.get("operation_name", "<NO_OPERATION>")
    a_c["request_ip"] = event.get("request_ip", "<NO_REQUESTIP>")
    return a_c
