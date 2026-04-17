from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if not all(
        [
            (event.get("name", "") == "CHANGE_CALENDAR_SETTING"),
            (event.deep_get("parameters", "SETTING_NAME", default="") == "SHARING_OUTSIDE_DOMAIN"),
        ]
    ):
        return False
    return event.deep_get("parameters", "NEW_VALUE", default="") in [
        "READ_WRITE_ACCESS",
        "READ_ONLY_ACCESS",
        "MANAGE_ACCESS",
    ]


def title(event):
    return (
        f"GSuite workspace setting for default calendar sharing was changed by "
        f"[{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}] "
        + f"from [{event.deep_get('parameters', 'OLD_VALUE', default='<NO_OLD_SETTING_FOUND>')}] "
        + f"to [{event.deep_get('parameters', 'NEW_VALUE', default='<NO_NEW_SETTING_FOUND>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
