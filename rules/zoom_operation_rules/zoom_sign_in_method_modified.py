def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = "Sign-in Methods  - Allow users to sign in with "
    setting_flag = "from Off to On"
    return all(
        [
            event.get("action", "<NO_ACTION>") == "Update",
            event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
            operation_detail.startswith(operation_flag),
            operation_detail.endswith(setting_flag),
        ]
    )


def title(event):
    # string manipulation to grab service that allows sign-in from the operation detail
    # and clean it up a bit
    service_detail = ""
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag = "Sign-in Methods  - Allow users to sign in with "
    setting_flag = "from Off to On"
    if operation_detail.startswith(operation_flag) and operation_detail.endswith(setting_flag):
        service_detail = (
            event.get("operation_detail", "<NO_OPS_DETAIL>").split("with")[1].split(":")[0].strip()
        )
    return (
        f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] modified your organization's "
        f"sign in methods to allow users to sign in with [{service_detail}]."
    )
