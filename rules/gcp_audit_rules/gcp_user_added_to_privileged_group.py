from panther_base_helpers import key_value_list_to_dict

PRIVILEGED_GROUPS = {
    # "admins@example.com"
}

USER_EMAIL = ""
GROUP_EMAIL = ""


def rule(event):
    events = event.deep_get("protoPayload", "metadata", "event")
    if len(events) != 1:
        return False

    event_ = events[0]
    if event_.get("eventname") != "ADD_GROUP_MEMBER":
        return False

    # Get the username
    params = key_value_list_to_dict(event_.get("parameter", []), "name", "value")
    global USER_EMAIL, GROUP_EMAIL  # pylint: disable=global-statement
    USER_EMAIL = params.get("USER_EMAIL", "<UNKNOWN USER>")
    GROUP_EMAIL = params.get("GROUP_EMAIL", "<UNKNOWN GROUP>")

    return GROUP_EMAIL in get_privileged_groups()


def title(event):
    actor = event.deep_get("actor", "email", default="")
    global USER_EMAIL, GROUP_EMAIL
    return f"{actor} has added {USER_EMAIL} to the privileged group {GROUP_EMAIL}"


def get_privileged_groups():
    # We make this a function, so we can mock it for unit tests
    return PRIVILEGED_GROUPS
