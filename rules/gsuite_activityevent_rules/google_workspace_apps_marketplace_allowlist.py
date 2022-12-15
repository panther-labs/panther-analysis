def rule(event):
    # Return True to match the log event and trigger an alert.
    setting_name = event.get("parameters", {}).get("SETTING_NAME", "NO_SETTING_NAME")
    old_val = event.get("parameters", {}).get("OLD_VALUE", "NO_OLD_VALUE_FOUND")
    new_val = event.get("parameters", {}).get("NEW_VALUE", "NO_NEW_VALUE_FOUND")
    return setting_name == "ENABLE_G_SUITE_MARKETPLACE" and old_val != new_val


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this
    # method will act as deduplication string.
    value_dict = {
        "DEFAULT": "DEFAULT",
        "1": "Don't allow users to install and run apps from the Marketplace",
        "2": "Allow users to install and run any app from the Marketplace",
        "3": "Allow users to install and run only selected apps from the Marketplace",
    }
    old_val = event.get("parameters", {}).get("OLD_VALUE", "NO_OLD_VALUE_FOUND")
    new_val = event.get("parameters", {}).get("NEW_VALUE", "NO_NEW_VALUE_FOUND")
    return (
        f"Google Workspace User [{event.get('actor',{}).get('email','no-email-provided')}] "
        f"made an application allowlist setting change from [{value_dict.get(old_val)}] "
        f"to [{value_dict.get(new_val)}]"
    )
