def rule(event):
    return True


def title(event):
    return (
        f"GSuite: [{event.get('user', '<user_not_found>')}] "
        f"downloaded [{event.get('download_count', '<count_not_found>')}] "
        "files from Google Drive."
    )


def alert_context(event):
    return event
