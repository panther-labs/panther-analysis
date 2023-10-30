def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = (
        "Require that all meetings are secured with one security option: from On to Off"
    )

    return (
        event.get("action", "<NO_ACTION>") == "Update"
        and event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account"
        and operation_flag in operation_detail
    )


def title(event):
    return (
        f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] turned off your organization's "
        f"requirement to secure all meetings with one security option."
    )
