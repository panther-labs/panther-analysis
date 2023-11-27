SENSITIVE_LOCAL_USERS = ["breakglass"]


def rule(event):
    return (
        event.get("event") == "user.login"
        and event.get("success") == "true"
        and event.get("method") == "local"
        and not event.get("mfa_device")
    )


def severity(event):
    if event.get("user") in SENSITIVE_LOCAL_USERS:
        return "HIGH"
    return "MEDIUM"


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into "
        f"[{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] locally "
        f"without using MFA"
    )
