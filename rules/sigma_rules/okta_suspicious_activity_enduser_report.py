def rule(event):
    if (
        event.deep_get("eventtype", default="")
        == "user.account.report_suspicious_activity_by_enduser"
    ):
        return True
    return False
