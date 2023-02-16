def rule(event):
    return all(
        [
            event.get("action") == "Update",
            event.get("category_type") == "Account",
            "Sign-In Password Requirement" in event.get("operation_detail"),
            "from On to Off" in event.get("operation_detail"),
        ]
    )


def title(event):
    actor = event.get("operator", "<OPERATOR_NOT_FOUND>")
    return f"Zoom Sign In Password Requirement Modified by [{actor}]"


# def dedup(event):
#  (Optional) Return a string which will be used to deduplicate similar alerts.
# return ''


def alert_context(event):
    return {"operation_detail": event.get("operation_detail")}
