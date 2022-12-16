def rule(event):
    # Return True to match the log event and trigger an alert.
    return event.get("action", "") == "bypass_view"


def title(event):
    # If no 'dedup' function is defined, the return value
    # of this method will act as deduplication string.
    return (
        f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed "
        f"an MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]."
    )
