from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if event.deep_get("id", "applicationName", default="").lower() != "admin":
        return False
    if all(
        [
            (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
            (event.get("type", "") == "APPLICATION_SETTINGS"),
            (event.deep_get("parameters", "NEW_VALUE", default="").lower() == "off"),
            (
                event.deep_get("parameters", "SETTING_NAME", default="")
                == "Password Management - Enforce strong password"
            ),
        ]
    ):
        return True
    return False


def title(event):
    return (
        f"GSuite Workspace Strong Password Enforcement Has Been Disabled "
        f"By [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
