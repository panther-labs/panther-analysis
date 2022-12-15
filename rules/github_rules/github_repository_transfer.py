from panther_base_helpers import github_alert_context


def rule(event):
    # Return True to match the log event and trigger an alert.
    return event.get("action", "") in (
        "repo.transfer",
        "repo.transfer_outgoing",
        "repo.transfer_start",
    )


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method
    # will act as deduplication string.
    action = event.get("action", "")
    if action == "repo.transfer":
        # return something like: A user accepted a request to receive a transferred repository.
        return (
            f"Github User [{event.get('actor','NO_ACTOR_FOUND')}] accepted a request to "
            f"receive repository [{event.get('repo','NO_REPO_NAME_FOUND')}] in "
            f"[{event.get('org','NO_ORG_NAME_FOUND')}]."
        )
    if action == "repo.transfer_outgoing":
        # return something like: A repository was transferred to another repository network.
        return (
            f"Github User [{event.get('actor','NO_ACTOR_FOUND')}] transferred repository "
            f"[{event.get('repo','NO_REPO_NAME_FOUND')}] in "
            f"[{event.get('org','NO_ORG_NAME_FOUND')}]."
        )
    if action == "repo.transfer_start":
        # return something like: A user sent a request to transfer a
        # repository to another user or organization.
        return (
            f"Github User [{event.get('actor','NO_ACTOR_FOUND')}] sent a request to "
            f"transfer repository [{event.get('repo','NO_REPO_NAME_FOUND')}] "
            f"to another user or organization."
        )

    return ""


def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert
    # sent to the SNS/SQS/Webhook destination
    return github_alert_context(event)
