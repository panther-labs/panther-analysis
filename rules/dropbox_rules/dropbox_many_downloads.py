def rule(_):
    return True


def title(event):
    return (
        f"Dropbox: [{event.get('user', '<user_not_found>')}] "
        f"has downloaded [{event.get('download_count', '<count_not_found>')}] "
        "documents from Google Drive."
    )


def alert_context(event):
    return event
