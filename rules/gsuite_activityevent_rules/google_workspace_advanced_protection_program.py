def rule(event):
    # Return True to match the log event and trigger an alert.
    setting_name = (
        event.get("parameters", {}).get("SETTING_NAME", "NO_SETTING_NAME").split("-")[0].strip()
    )
    setting_alert_flag = "Advanced Protection Program Settings"
    return event.get("name") == "CREATE_APPLICATION_SETTING" and setting_name == setting_alert_flag


def title(event):
    # If no 'dedup' function is defined, the return value of this
    # method will act as deduplication string.
    setting = event.get("parameters", {}).get("SETTING_NAME", "NO_SETTING_NAME")
    setting_name = setting.split("-")[-1].strip()
    return (
        f"Google Workspace Advanced Protection Program settings have been updated to "
        f"[{setting_name}]"
    )
