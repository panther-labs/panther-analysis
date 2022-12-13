from panther_base_helpers import github_alert_context


def rule(event):
    # Return True to match the log event and trigger an alert.
    # Creates a new alert if the event's action was ""
    return event.get("action") == "integration_installation.create"


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method
    # will act as deduplication string.
    return (
        f" Github User '{event.get('actor',{})}' in '{event.get('org')}' "
        f"installed the following integration: '{event.get('name')}'."
    )


# def dedup(event):
#  (Optional) Return a string which will be used to deduplicate similar alerts.
# return ''


def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the
    #  alert sent to the SNS/SQS/Webhook destination
    return github_alert_context(event)
