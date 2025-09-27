from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    if all(
        [
            (event.get("type", "") == "EMAIL_SETTINGS"),
            (event.get("name", "").endswith("_GMAIL_SETTING")),
            (event.deep_get("parameters", "SETTING_NAME", default="") == "MESSAGE_SECURITY_RULE"),
        ]
    ):
        return True
    return False


def title(event):
    # Gmail records the event name as DELETE_GMAIL_SETTING/CREATE_GMAIL_SETTING
    # We shouldn't be able to enter title() unless event[name] ends with
    #  _GMAIL_SETTING, and as such change_type assumes the happy path.
    change_type = f"{event.get('name', '').split('_')[0].lower()}d"
    return (
        f"GSuite Gmail Default Routing Rule Was "
        f"[{change_type}] "
        f"by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
