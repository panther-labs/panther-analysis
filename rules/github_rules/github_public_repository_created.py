from panther_base_helpers import github_alert_context


def rule(event):
    # Return True if a public repository was created
    return event.get("action", "") == "repo.create" and event.get("visibility", "") == "public"


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method
    # will act as deduplication string.
    return (
        f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] "
        f"created with public status by Github user [{event.get('actor')}]."
    )


# def dedup(event):
#  (Optional) Return a string which will be used to deduplicate similar alerts.
# return ''


def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert
    # sent to the SNS/SQS/Webhook destination
    return github_alert_context(event)
