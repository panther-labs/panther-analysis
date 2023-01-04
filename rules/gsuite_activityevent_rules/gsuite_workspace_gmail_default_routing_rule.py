from panther_base_helpers import deep_get


def rule(event):
    if all(
        [
            (event.get("type", "") == "EMAIL_SETTINGS"),
            (event.get("name", "").endswith("_GMAIL_SETTING")),
            (deep_get(event, "parameters", "SETTING_NAME", default="") == "MESSAGE_SECURITY_RULE"),
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
        f"by [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
