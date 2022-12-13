from panther_base_helpers import deep_get


def rule(event):
    if (
        not event.get("name", "") != "CHANGE_CALENDAR_SETTING"
        and not deep_get(event, "parameters", "SETTING_NAME", default="")
        == "SHARING_OUTSIDE_DOMAIN"
    ):
        return False
    return deep_get(event, "parameters", "NEW_VALUE", default="") in [
        "READ_WRITE_ACCESS",
        "READ_ONLY_ACCESS",
        "MANAGE_ACCESS",
    ]


def title(event):
    return (
        f"GSuite workspace setting for default calendar sharing was changed by "
        f"[{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] "
        f"from [{deep_get(event, 'parameters', 'OLD_VALUE', default='<NO_OLD_SETTING_FOUND>')}] "
        f"to [{deep_get(event, 'parameters', 'NEW_VALUE', default='<NO_NEW_SETTING_FOUND>')}]"
    )
