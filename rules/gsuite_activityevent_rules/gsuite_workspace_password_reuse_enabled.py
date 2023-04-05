from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName", default="").lower() != "admin":
        return False

    new_value = (deep_get(event, "parameters", "NEW_VALUE", default="") or "").lower()
    if all(
        [
            (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
            (event.get("type", "") == "APPLICATION_SETTINGS"),
            (new_value == "true"),
            (
                deep_get(event, "parameters", "SETTING_NAME", default="")
                == "Password Management - Enable password reuse"
            ),
        ]
    ):
        return True
    return False


def title(event):
    return (
        f"GSuite Workspace Password Reuse Has Been Enabled "
        f"By [{deep_get(event, 'actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )
