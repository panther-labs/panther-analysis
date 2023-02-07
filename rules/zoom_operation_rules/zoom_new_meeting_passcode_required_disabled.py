def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = "Security  - Require a passcode when scheduling new meetings: from On to Off"
    return (
        event.get("action", "<NO_ACTION>") == "Update"
        and event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account"
        and operation_flag == operation_detail
    )


def title(event):
    return (
        f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off "
        f"your organization's setting to require passcodes for new meetings."
    )
