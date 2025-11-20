HOSTNAME = ""


def rule(event):

    return all(
        [
            event.get("operationName", "").lower() == "compliance",
            event.deep_get("properties", "AlertType", default="").lower()
            == "managed device not compliant",
        ]
    )


def title(event):
    # pylint: disable=global-statement
    global HOSTNAME

    # Simple title with hostname of the non-compliant device
    HOSTNAME = event.deep_get("properties", "DeviceHostName", default="Unknown")

    return f"INTUNE: [{HOSTNAME}] reported as non-compliant"


def alert_context(event):
    return {
        "Hostname": HOSTNAME,
        "Operating System": event.deep_get(
            "properties", "DeviceOperatingSystem", default="Unknown"
        ),
        "User": event.deep_get("properties", "UserName", default="Unknown"),
        "User Display Name": event.deep_get("properties", "UserDisplayName", default="Unknown"),
        "Description": event.deep_get("properties", "Description", default="Unknown"),
    }
