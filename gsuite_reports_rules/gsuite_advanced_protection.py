from panther_base_helpers import deep_get, gsuite_details_lookup as details_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "user_accounts":
        return False

    return bool(details_lookup("titanium_change", ["titanium_unenroll"], event))


def title(event):
    return "Advanced protection was disabled for user [{}]".format(
        deep_get(event, "actor", "email", default="<UNKNOWN_EMAIL>")
    )
