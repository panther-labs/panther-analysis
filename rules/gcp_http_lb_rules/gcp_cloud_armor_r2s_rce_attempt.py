# CloudArmor signature IDs for CVE-2025-55182
REACT2SHELL_SIGNATURES = [
    "google-mrs-v202512-id000001-rce",
    "google-mrs-v202512-id000002-rce",
]


def rule(event):
    # Check that this is an HTTP load balancer event
    if event.deep_get("resource", "type") != "http_load_balancer":
        return False

    # Check enforced policy match
    enforced_policy = event.deep_get("jsonPayload", "enforcedSecurityPolicy", default={})
    enforced_sigs = enforced_policy.get("preconfiguredExprIds", [])
    if any(sig in enforced_sigs for sig in REACT2SHELL_SIGNATURES):
        return True

    # Check preview policy for non-blocking WAF matches
    preview_policy = event.deep_get("jsonPayload", "previewSecurityPolicy", default={})
    preview_sigs = preview_policy.get("preconfiguredExprIds", [])
    if any(sig in preview_sigs for sig in REACT2SHELL_SIGNATURES):
        return True

    return False


def title(event):
    remote_ip = event.deep_get("httpRequest", "remoteIp", default="<UNKNOWN_IP>")
    return f"Cloud Armor React2Shell (CVE-2025-55182) Exploit Detected from {remote_ip}"


def alert_context(event):
    enforced_policy = event.deep_get("jsonPayload", "enforcedSecurityPolicy", default={})
    preview_policy = event.deep_get("jsonPayload", "previewSecurityPolicy", default={})
    http_request = event.get("httpRequest", {})
    status_details = event.deep_get("jsonPayload", "statusDetails", default="<UNKNOWN_STATUS>")

    context = {
        "vulnerability": "CVE-2025-55182 (React2Shell)",
        "status_details": status_details,
        "remote_ip": http_request.get("remoteIp"),
        "request_url": http_request.get("requestUrl"),
        "request_method": http_request.get("requestMethod"),
        "user_agent": http_request.get("userAgent"),
        "status_code": http_request.get("status"),
        "referer": http_request.get("referer"),
        "enforced_policy": {
            "name": enforced_policy.get("name"),
            "configured_action": enforced_policy.get("configuredAction"),
            "outcome": enforced_policy.get("outcome"),
            "priority": enforced_policy.get("priority"),
            "signature_ids": enforced_policy.get("preconfiguredExprIds", []),
            "matched_field_type": enforced_policy.get("matchedFieldType"),
            "matched_field_name": enforced_policy.get("matchedFieldName"),
            "matched_field_value": enforced_policy.get("matchedFieldValue"),
            "matched_length": enforced_policy.get("matchedLength"),
        },
        "project_id": event.deep_get("resource", "labels", "project_id"),
        "backend_service": event.deep_get("resource", "labels", "backend_service_name"),
        "forwarding_rule": event.deep_get("resource", "labels", "forwarding_rule_name"),
    }

    # Include preview policy details if present
    if preview_policy:
        context["preview_policy"] = {
            "configured_action": preview_policy.get("configuredAction"),
            "outcome": preview_policy.get("outcome"),
            "priority": preview_policy.get("priority"),
            "signature_ids": preview_policy.get("preconfiguredExprIds", []),
            "matched_field_type": preview_policy.get("matchedFieldType"),
            "matched_field_name": preview_policy.get("matchedFieldName"),
            "matched_field_value": preview_policy.get("matchedFieldValue"),
            "matched_length": preview_policy.get("matchedLength"),
        }

    return context
