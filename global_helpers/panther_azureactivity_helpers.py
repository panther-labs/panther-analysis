def azure_activity_alert_context(event) -> dict:
    a_c = {}
    a_c["resource_id"] = event.get("resourceId", "<UNKNOWN_RESOURCE_ID>")
    a_c["caller_ip"] = event.get("callerIpAddress", "<UNKNOWN_CALLER_IP>")
    a_c["operation_name"] = event.get("operationName", "<UNKNOWN_OPERATION_NAME>")
    a_c["result_type"] = event.get("resultType", "<UNKNOWN_RESULT_TYPE>")
    a_c["correlation_id"] = event.get("correlationId", "<UNKNOWN_CORRELATION_ID>")
    a_c["location"] = event.get("location", "<UNKNOWN_LOCATION>")
    a_c["tenant_id"] = event.get("tenantId", "<UNKNOWN_TENANT_ID>")
    return a_c


def azure_activity_success(event):
    result = event.get("resultType", "")
    if result in ["Success", "Succeeded"]:
        return True
    return False


def azure_resource_logs_success(event):
    response_type = event.deep_get("properties", "metricResponseType", default="")
    if response_type == "Success":
        return True
    return False


def azure_resource_logs_failure(event):
    response_type = event.deep_get("properties", "metricResponseType", default="")
    if response_type != "Success":
        return True
    return False
