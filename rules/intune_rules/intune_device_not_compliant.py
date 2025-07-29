from panther_base_helpers import deep_get


def rule(event):
    # Alert when the AlertType is "Managed Device Not Compliant"
    return deep_get(event, "properties", "AlertType") == "Managed Device Not Compliant"


def title(event):
    hostname = deep_get(event, "properties", "DeviceHostName", default="Unknown")
    return f"InTune reports that the device [{hostname}] is not compliant"


def alert_context(event):
    return {
        "Hostname": deep_get(event, "properties", "DeviceHostName", default="Unknown"),
        "Operating System": deep_get(
            event, "properties", "DeviceOperatingSystem", default="Unknown"
        ),
        "User": deep_get(event, "properties", "UserName", default="Unknown"),
        "Description": deep_get(event, "properties", "Description", default="Unknown"),
    }
