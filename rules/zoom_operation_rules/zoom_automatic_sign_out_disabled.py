def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = "Automatically sign users out after a specified time: from On to Off"
    return all(
        [
            event.get("action", "<NO_ACTION>") == "Update",
            event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
            operation_flag in operation_detail
        ]
    )


def title(event):
    return (
        f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's "
        f"setting to automatically sign users out after a specified time."
    )
