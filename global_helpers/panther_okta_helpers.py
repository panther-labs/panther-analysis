from panther_base_helpers import pantherflow_investigation


def okta_alert_context(event):
    """Returns common context for automation of Okta alerts"""
    return {
        "event_type": event.get("eventtype", ""),
        "severity": event.get("severity", ""),
        "actor": event.get("actor", {}),
        "client": event.get("client", {}),
        "request": event.get("request", {}),
        "outcome": event.get("outcome", {}),
        "target": event.get("target", []),
        "debug_context": event.get("debugcontext", {}),
        "authentication_context": event.get("authenticationcontext", {}),
        "security_context": event.get("securitycontext", {}),
        "ips": event.get("p_any_ip_addresses", []),
        "PantherFlow Investigation": pantherflow_investigation(event),
    }
