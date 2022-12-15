def rule(event):
    # Return True to match the log event and trigger an alert.
    setting_name = (
        event.get("parameters", {}).get("SETTING_NAME", "NO_SETTING_NAME").split("-")[0].strip()
    )
    setting_alert_flag = "Advanced Protection Program Settings"
    return event.get("name") == "CREATE_APPLICATION_SETTING" and setting_name == setting_alert_flag


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this
    # method will act as deduplication string.
    setting = event.get("parameters", {}).get("SETTING_NAME", "NO_SETTING_NAME")
    setting_name = setting.split("-")[-1].strip()
    return (
        f"Google Workspace Advanced Protection Program settings have been updated to "
        f"[{setting_name}]"
    )


# def dedup(event):
#  (Optional) Return a string which will be used to deduplicate similar alerts.
# return ''

# def alert_context(event):
# (Optional) Return a dictionary with additional data to be included in
# the alert sent to the SNS/SQS/Webhook destination
# return {'key':'value'}
