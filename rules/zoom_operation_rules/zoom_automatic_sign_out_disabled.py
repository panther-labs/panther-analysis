def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = "Automatically sign users out after a specified time: from On to Off"
    return (
        event.get("action", "<NO_ACTION>") == "Update"
        and event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account"
        and operation_flag in operation_detail
    )


def generate_alert_title(event):
    return (
        f"ALERT: Zoom User [{event.get('operator', '<NO_OPERATOR>')}] disabled automatic sign-out "
        f"for your organization."
    )
