def rule(event):
    if all(
        [
            event.deep_get("outcome", "reason", default="") == "FastPass declined phishing attempt",
            event.deep_get("outcome", "result", default="") == "FAILURE",
            event.deep_get("eventtype", default="") == "user.authentication.auth_via_mfa",
        ]
    ):
        return True
    return False
