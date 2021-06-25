from panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION


def rule(event):
    return (
        event.get("source_type") == "user_setting"
        and event.get("action", "")
        in {
            "create",
            "update",
        }
        and "suspended" in event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower()
    )


def title(event):
    suspension_status = event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower()
    user = event.get("source_label", "<UNKNOWN_USER>").split(":")
    if len(user) > 1:
        user = user[1].strip()
    return f"Actor user [{event.udm('actor_user')}] {suspension_status} user [{user}]"


def severity(event):
    if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "suspended":
        return "INFO"
    return "HIGH"
