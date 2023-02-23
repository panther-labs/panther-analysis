def rule(event):
    operation_detail = event.get("operation_detail", "<NO_OPS_DETAIL>")
    operation_flag_one = "Sign-In Password Requirement"
    operation_flag_two = "Off"
    return all(
        [
            event.get("action", "<NO_ACTION>") == "Update",
            event.get("category_type", "<NO_CATEGORY_TYPE>") == "Account",
            operation_flag_one in operation_detail,
            operation_flag_two in operation_detail,
        ]
    )


def title(event):
    return (
        f"Zoom User [{event.get('operator', '<NO_OPERATOR>')}] changed your organization's "
        f"sign in requirements [{event.get('operation_detail', '<NO_OPS_DETAIL>')}]."
    )
