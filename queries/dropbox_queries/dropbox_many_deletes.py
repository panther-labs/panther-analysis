def rule(_):
    return True


def title(event):
    return (
        f"Dropbox: [{event.get('user', '<user_not_found>')}] "
        f"has deleted [{event.get('delete_count', '<count_not_found>')}] "
        "documents from Dropbox."
    )


def alert_context(event):
    return event.to_dict()
