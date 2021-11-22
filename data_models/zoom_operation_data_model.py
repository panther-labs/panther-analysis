import panther_event_type_helpers as event_type


def get_event_type(event):
    # pylint: disable=too-many-return-statements
    if event.get("category_type") == "User":
        if event.get("action") == "Add":
            return event_type.USER_ACCOUNT_CREATED
        if event.get("action") == "Delete":
            return event_type.USER_ACCOUNT_DELETED
        if event.get("action") == "Update":
            return event_type.USER_ACCOUNT_MODIFIED

    if event.get("category_type") == "User Group":
        if event.get("action") == "Add":
            return event_type.USER_GROUP_CREATED
        if event.get("action") == "Update":
            return event_type.USER_GROUP_MODIFIED
        if event.get("action") == "Delete":
            return event_type.USER_GROUP_DELETED

    if event.get("category_type") == "Role":
        if event.get("action") == "Add":
            return event_type.USER_ROLE_CREATED
        if event.get("action") == "Update":
            return event_type.USER_ROLE_MODIFIED
        if event.get("action") == "Delete":
            return event_type.USER_ROLE_DELETED
    return None
