def rule(_):
    return True


def title(event):
    return (
        f"GSuite: [{event.get('user', '<user_not_found>')}] "
        f"has deleted [{event.get('delete_count', '<count_not_found>')}] "
        "documents from Google Drive."
    )


def alert_context(event):
    return event
