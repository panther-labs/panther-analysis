def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = "Security  - Sign in with Two-Factor Authentication: from On to Off"
    return all(
        [
            event.get("action", "<NO_ACTION>") == "Update",
            event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
            operation_detail == operation_flag,
        ]
    )


def generate_alert_title(event):
    return (
        f"ALERT: Zoom User [{event.get('operator', '<NO_OPERATOR>')}] disabled Two-Factor Authentication "
        f"for your organization."
    )
