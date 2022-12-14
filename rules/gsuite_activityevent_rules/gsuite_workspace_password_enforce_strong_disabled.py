from panther_base_helpers import deep_get


def rule(event):
    if all(
        [
            (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
            (event.get("type", "") == "APPLICATION_SETTINGS"),
            (deep_get(event, "parameters", "NEW_VALUE", default="").lower() == "off"),
            (
                deep_get(event, "parameters", "SETTING_NAME", default="")
                == "Password Management - Enforce strong password"
            ),
        ]
    ):
        return True
    return False


def title(event):
    return (
        f"GSuite Workspace Strong Password Enforcement Has Been Disabled "
        f"By [{deep_get(event, 'actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )
