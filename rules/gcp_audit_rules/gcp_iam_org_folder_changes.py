def rule(event):
    # Return True to match the log event and trigger an alert.
    logname = event.get("logName")
    return (
        event.deep_get("protoPayload", "methodName") == "SetIamPolicy"
        and (logname.startswith("organizations") or logname.startswith("folder"))
        and logname.endswith("/logs/cloudaudit.googleapis.com%2Factivity")
    )


def title(event):
    # use unified data model field in title
    return (
        f"{event.get('p_log_type')}: [{event.udm('actor_user')}] made manual changes to Org policy"
    )


def alert_context(event):
    return {
        "actor": event.udm("actor_user"),
        "policy_change": event.deep_get("protoPayload", "serviceData", "policyDelta"),
        "caller_ip": event.deep_get("protoPayload", "requestMetadata", "callerIP"),
        "user_agent": event.deep_get("protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
    }


def severity(event):
    if (
        event.deep_get("protoPayload", "requestMetadata", "callerSuppliedUserAgent")
        .lower()
        .find("terraform")
        != -1
    ):
        return "INFO"
    return "HIGH"
