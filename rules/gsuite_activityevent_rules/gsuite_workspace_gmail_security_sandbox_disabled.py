from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if event.deep_get("id", "applicationName", default="").lower() != "admin":
        return False
    if all(
        [
            (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
            (event.deep_get("parameters", "APPLICATION_NAME", default="").lower() == "gmail"),
            (event.deep_get("parameters", "NEW_VALUE", default="").lower() == "false"),
            (
                event.deep_get("parameters", "SETTING_NAME", default="")
                == "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
            ),
        ]
    ):
        return True
    return False


def title(event):
    return (
        f"GSuite Gmail Security Sandbox was disabled "
        f"for [{event.deep_get('parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] "
        f"by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
