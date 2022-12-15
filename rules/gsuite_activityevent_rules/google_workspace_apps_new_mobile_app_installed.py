def rule(event):
    # Return True to match the log event and trigger an alert.
    return event.get("name", "") == "ADD_MOBILE_APPLICATION_TO_WHITELIST"


def title(event):
    # If no 'dedup' function is defined, the return value of
    # this method will act as deduplication string.
    mobile_app_pkg_id = event.get("parameters", {}).get(
        "MOBILE_APP_PACKAGE_ID", "<NO_MOBILE_APP_PACKAGE_ID_FOUND>"
    )
    return (
        f"Google Workspace User [{event.get('actor',{}).get('email','<NO_EMAIL_FOUND>')}] "
        f"added application "
        f"[{mobile_app_pkg_id}] "
        f"to your organization's mobile application whitelist for the device type "
        f"[{event.get('parameters',{}).get('DEVICE_TYPE','<NO_DEVICE_TYPE_FOUND>')}]."
    )
