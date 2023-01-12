from panther_base_helpers import deep_get


def rule(event):
    if not deep_get(event, "id", "applicationName", default="").lower() == "admin":
        return False
    if all(
        [
            (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
            (deep_get(event, "parameters", "APPLICATION_NAME", default="").lower() == "gmail"),
            (deep_get(event, "parameters", "NEW_VALUE", default="").lower() == "false"),
            (
                deep_get(event, "parameters", "SETTING_NAME", default="")
                == "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
            ),
        ]
    ):
        return True
    return False


def title(event):
    return (
        f"GSuite Gmail Security Sandbox was disabled "
        f"for [{deep_get(event, 'parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] "
        f"by [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
