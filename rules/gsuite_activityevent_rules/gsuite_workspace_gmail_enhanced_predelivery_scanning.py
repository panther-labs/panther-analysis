from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    # the shape of the items in parameters can change a bit ( like NEW_VALUE can be an array )
    #  when the applicationName is something other than admin
    if event.deep_get("id", "applicationName", default="").lower() != "admin":
        return False
    if all(
        [
            (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
            (event.deep_get("parameters", "APPLICATION_NAME", default="").lower() == "gmail"),
            (event.deep_get("parameters", "NEW_VALUE", default="").lower() == "true"),
            (
                event.deep_get("parameters", "SETTING_NAME", default="")
                == "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
            ),
        ]
    ):
        return True
    return False


def title(event):
    return (
        f"GSuite Gmail Enhanced Pre-Delivery Scanning was disabled "
        f"for [{event.deep_get('parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] "
        f"by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
